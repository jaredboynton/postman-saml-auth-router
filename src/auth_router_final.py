#!/usr/bin/env python3
"""Postman SAML Enforcement Daemon for Enterprise MDM Deployment.

This daemon intercepts Postman Desktop authentication requests and enforces
SAML-only authentication by redirecting users directly to the configured
enterprise SSO provider, bypassing team selection and auth method choice.

Designed for enterprise MDM deployment with ZERO external dependencies.
Uses only Python standard library for maximum compatibility and security.

Usage:
    sudo python3 auth_router_final.py [--config config.json] [--mode enforce|monitor]

Enterprise Features:
    - State machine tracking of authentication flow
    - Dynamic hosts file management (optional)
    - Comprehensive logging and metrics
    - Health check endpoint for monitoring
    - Graceful handling of certificate updates
    - Support for multiple IdP providers

Author: Enterprise Security Team
Version: 2.0.0
"""

import http.server
import json
import logging
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from enum import Enum
from http.client import HTTPSConnection, HTTPConnection
from pathlib import Path
from typing import Dict, Optional, Tuple, Any, List

# Configure logging
def setup_logging(log_file=None, max_bytes=10485760, backup_count=5):
    """Set up logging configuration with rotation support.
    
    Args:
        log_file: Path to log file (default: /var/log/postman-auth.log)
        max_bytes: Maximum size of log file before rotation (default: 10MB)
        backup_count: Number of backup files to keep (default: 5)
    """
    if log_file is None:
        log_file = '/var/log/postman-auth.log'
    
    handlers = [logging.StreamHandler()]
    
    # Try to add rotating file handler if we have permission
    try:
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file, 
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        handlers.append(file_handler)
    except (PermissionError, OSError, ImportError):
        # Running without root or RotatingFileHandler not available
        # Fall back to regular FileHandler
        try:
            file_handler = logging.FileHandler(log_file, mode='a')
            file_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )
            handlers.append(file_handler)
        except (PermissionError, OSError):
            # Can't write to file, console only
            pass
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
    return logging.getLogger('postman-auth')

logger = setup_logging()


class DNSResolver:
    """Resolves real IP addresses for domains to avoid proxy loops.
    
    When /etc/hosts redirects domains to 127.0.0.1, we need to resolve
    the real IPs to proxy requests upstream. Uses a hybrid approach for
    maximum enterprise compatibility:
    
    1. Primary: nslookup (universally available, firewall-friendly)
    2. Fallback: DNS-over-HTTPS via curl (when nslookup fails)
    3. Last resort: Configured fallback IPs
    
    The resolution method can be configured via dns_resolution_method in
    config.json to override the default hybrid behavior for specific
    enterprise environments.
    
    Attributes:
        cache: Cache of resolved domain->IP mappings
        dns_server: External DNS server to use (default: 8.8.8.8)
        fallback_ips: Dictionary of hostname->IP fallback mappings
        resolution_method: Method to use ('auto', 'nslookup', 'doh')
    """
    
    def __init__(self, dns_server: str = '8.8.8.8', fallback_ips: Optional[Dict[str, str]] = None, 
                 resolution_method: str = 'auto'):
        """Initialize DNS resolver.
        
        Args:
            dns_server: External DNS server to use for resolution
            fallback_ips: Fallback IP addresses for known domains
            resolution_method: Resolution method ('auto', 'nslookup', 'doh')
        """
        self.cache: Dict[str, str] = {}
        self.dns_server = dns_server
        self.fallback_ips = fallback_ips or {}
        self.resolution_method = resolution_method
        self._lock = threading.Lock()
    
    def resolve(self, hostname: str) -> str:
        """Resolve hostname to real IP address using hybrid approach.
        
        Uses the configured resolution method or automatic fallback:
        1. nslookup (enterprise-friendly, universally available)
        2. DNS-over-HTTPS (when nslookup fails or is unavailable)
        3. Configured fallback IPs (last resort)
        
        Args:
            hostname: Domain name to resolve
            
        Returns:
            IP address of the domain
            
        Raises:
            ValueError: If hostname resolution fails completely
        """
        with self._lock:
            # Check cache first
            if hostname in self.cache:
                return self.cache[hostname]
            
            ip = None
            
            # Try resolution methods based on configuration
            if self.resolution_method in ('auto', 'nslookup'):
                ip = self._resolve_with_nslookup(hostname)
                if ip:
                    self.cache[hostname] = ip
                    logger.info(f"Resolved {hostname} to {ip} via nslookup")
                    return ip
            
            if self.resolution_method in ('auto', 'doh') and not ip:
                ip = self._resolve_with_doh(hostname)
                if ip:
                    self.cache[hostname] = ip
                    logger.info(f"Resolved {hostname} to {ip} via DNS-over-HTTPS")
                    return ip
            
            # Fallback to configured IPs for known domains
            if not self.fallback_ips:
                # Default fallbacks if none configured
                self.fallback_ips = {
                    'identity.getpostman.com': '104.18.36.161',
                    'identity.postman.co': '104.18.37.186',
                    'identity.postman.com': '104.18.37.161'
                }
            
            ip = self.fallback_ips.get(hostname, '104.18.36.161')
            self.cache[hostname] = ip
            logger.warning(f"Using fallback IP for {hostname}: {ip}")
            return ip

    def _resolve_with_nslookup(self, hostname: str) -> Optional[str]:
        """Resolve hostname using nslookup command.
        
        Uses nslookup to query external DNS server, bypassing /etc/hosts.
        This is the most enterprise-compatible method as it works through
        corporate firewalls and doesn't require special access.
        
        Args:
            hostname: Domain name to resolve
            
        Returns:
            IP address if resolution succeeds, None otherwise
        """
        try:
            # Use nslookup with external DNS server
            result = subprocess.run(
                ['nslookup', hostname, self.dns_server],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout:
                # Parse nslookup output for Address: lines
                # Example output contains lines like "Address: 104.18.36.161"
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('Address:') and not line.endswith('#53'):
                        # Extract IP after "Address: "
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            ip = parts[1].strip()
                            if self._is_valid_ip(ip):
                                return ip
            
            logger.debug(f"nslookup failed for {hostname}: {result.stderr}")
            return None
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"nslookup command failed for {hostname}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in nslookup for {hostname}: {e}")
            return None

    def _resolve_with_doh(self, hostname: str) -> Optional[str]:
        """Resolve hostname using DNS-over-HTTPS.
        
        Queries Cloudflare's DNS-over-HTTPS service as fallback when
        nslookup is unavailable or fails. May be blocked in some
        enterprise environments.
        
        Args:
            hostname: Domain name to resolve
            
        Returns:
            IP address if resolution succeeds, None otherwise
        """
        try:
            # Query Cloudflare's DNS-over-HTTPS service
            dns_url = f"https://1.1.1.1/dns-query?name={hostname}&type=A"
            result = subprocess.run(
                ['curl', '-s', '-H', 'Accept: application/dns-json', dns_url],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                import json
                try:
                    dns_response = json.loads(result.stdout)
                    # Extract A records from the response
                    if 'Answer' in dns_response:
                        for answer in dns_response['Answer']:
                            if answer.get('type') == 1:  # A record
                                ip = answer.get('data')
                                if ip and self._is_valid_ip(ip):
                                    return ip
                except json.JSONDecodeError:
                    logger.debug(f"Invalid JSON response from DNS-over-HTTPS for {hostname}")
            
            logger.debug(f"DNS-over-HTTPS failed for {hostname}")
            return None
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"DNS-over-HTTPS command failed for {hostname}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in DNS-over-HTTPS for {hostname}: {e}")
            return None

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address.
        
        Args:
            ip: String to validate as IP address
            
        Returns:
            True if valid IPv4 address, False otherwise
        """
        try:
            parts = ip.split('.')
            return (len(parts) == 4 and 
                   all(p.isdigit() and 0 <= int(p) <= 255 for p in parts))
        except:
            return False


class AuthState(Enum):
    """Authentication flow states for the state machine."""
    IDLE = "idle"
    AUTH_INIT = "auth_init"
    LOGIN_REDIRECT = "login_redirect"
    SAML_FLOW = "saml_flow"
    OAUTH_CONTINUATION = "oauth_continuation"
    COMPLETE = "complete"


class OperationMode(Enum):
    """Operation modes for the daemon."""
    ENFORCE = "enforce"  # Force SAML authentication
    MONITOR = "monitor"  # Log but don't redirect
    TEST = "test"       # Test mode with verbose logging


class AuthStateMachine:
    """Tracks authentication flow state for proper interception.
    
    This state machine ensures we only intercept at the right points
    in the authentication flow to avoid breaking OAuth continuation.
    
    State Machine Diagram:
    ┌─────┐    /client/login or /login  ┌───────────┐
    │IDLE │ ──────────────────────────→ │AUTH_INIT  │
    └─────┘                             └───────────┘
       ↑                                       │
       │                                       │ /login?auth_challenge=...
       │ timeout (30s)                         ↓
       │                                ┌──────────────┐
       │                                │LOGIN_REDIRECT│
       │                                └──────────────┘
       │                                       │
       │                                       │ redirect to SAML
       │                                       ↓
       │                                ┌─────────────┐
       │                                │SAML_FLOW    │
       │                                └─────────────┘
       │                                       │
       │                                       │ /continue detected
       │                                       ↓
       │                                ┌──────────────────┐
       │                                │OAUTH_CONTINUATION│◄──┐
       │                                └──────────────────┘   │
       │                                       │               │
       │                                       │ /browser-auth │ OAuth timeout
       │                                       │ /success      │ (30s)
       │                                       ↓               │
       │ reset after 5s                 ┌─────────────┐        │
       └──────────────────────────────  │COMPLETE     │────────┘
                                        └─────────────┘
    
    Critical Rules:
    - NEVER intercept during OAUTH_CONTINUATION state
    - OAuth timeout (30s) prevents stuck sessions  
    - identity.postman.com hosts OAuth state validation
    - Breaking OAuth chain causes 401 authentication errors
    
    Attributes:
        current_state: Current state in the authentication flow
        session_data: Data collected during the current session
        state_timeout: Timeout for resetting stuck sessions
        oauth_timeout_seconds: Specific timeout for OAuth continuation (30s)
        metrics: Performance and security metrics
    """
    
    def __init__(self, timeout_seconds: int = 30, oauth_timeout_seconds: int = 30):
        """Initialize the state machine.
        
        Args:
            timeout_seconds: Seconds before resetting a stuck session
        """
        self.current_state = AuthState.IDLE
        self.session_data: Dict[str, Any] = {}
        self.state_entered_at = datetime.now()
        self.timeout_seconds = timeout_seconds
        self.oauth_timeout_seconds = oauth_timeout_seconds
        self.metrics = {
            'auth_attempts': 0,
            'saml_redirects': 0,
            'bypass_attempts': 0,
            'successful_auths': 0,
            'failed_auths': 0
        }
        self._lock = threading.Lock()
    
    def transition_to(self, new_state: AuthState, data: Optional[Dict] = None) -> None:
        """Transition to a new state.
        
        Args:
            new_state: The state to transition to
            data: Optional data to store for this transition
        """
        with self._lock:
            old_state = self.current_state
            self.current_state = new_state
            self.state_entered_at = datetime.now()
            
            if data:
                self.session_data.update(data)
            
            logger.info(f"State transition: {old_state.value} -> {new_state.value}")
            
            # Reset session data when returning to IDLE
            if new_state == AuthState.IDLE:
                self.session_data = {}
    
    def should_intercept(self, host: str, path: str) -> bool:
        """Determine if a request should be intercepted based on current state.
        
        Args:
            host: The hostname of the request
            path: The path of the request
            
        Returns:
            True if the request should be intercepted, False otherwise
        """
        with self._lock:
            # Check for timeout
            if self._is_timed_out():
                logger.warning("Session timed out, resetting to IDLE")
                self.current_state = AuthState.IDLE
                self.session_data = {}
            
            # State-based interception rules
            if self.current_state == AuthState.IDLE:
                # Start tracking when we see initial auth (Desktop or Browser flow)
                if host == "identity.getpostman.com" and ("/client" in path or path.startswith("/login")):
                    self.current_state = AuthState.AUTH_INIT
                    self.state_entered_at = datetime.now()
                    self.metrics['auth_attempts'] += 1
                    # For browser flows starting directly at /login, intercept immediately
                    if path.startswith("/login") and "/client" not in path:
                        return True  # Intercept browser login
                    return False  # Pass through Desktop client requests
            
            elif self.current_state == AuthState.AUTH_INIT:
                # Intercept login page to force SAML
                if host == "identity.getpostman.com" and path.startswith("/login"):
                    self.current_state = AuthState.LOGIN_REDIRECT
                    self.state_entered_at = datetime.now()
                    return True  # Intercept and redirect
            
            elif self.current_state == AuthState.LOGIN_REDIRECT:
                # We're redirecting to SAML
                if "/sso/" in path:
                    self.current_state = AuthState.SAML_FLOW
                    self.state_entered_at = datetime.now()
                    return False  # Let SAML flow proceed
            
            elif self.current_state == AuthState.SAML_FLOW:
                # SAML is in progress - check for OAuth continuation on Postman domains
                if ("/continue" in path and 
                    host in ["identity.postman.co", "identity.postman.com"]):
                    self.current_state = AuthState.OAUTH_CONTINUATION
                    self.state_entered_at = datetime.now()
                    return False  # CRITICAL: Don't intercept OAuth continuation
            
            elif self.current_state == AuthState.OAUTH_CONTINUATION:
                # OAuth continuation in progress - track but don't intercept!
                
                # Check for OAuth-specific timeout
                if (datetime.now() - self.state_entered_at).seconds > self.oauth_timeout_seconds:
                    logger.info("OAuth continuation timeout (30s) - resetting to IDLE")
                    self.current_state = AuthState.IDLE
                    self.session_data = {}
                    return False
                
                # Track id.gw.postman.com for state transition (but don't intercept)
                if host == "id.gw.postman.com":
                    logger.info(f"OAuth flow reached id.gw.postman.com{path} - tracking but not intercepting")
                    # Could transition to a new state here if needed
                    # But always return False to let it pass through naturally
                    return False
                
                # Check for successful completion
                if "/browser-auth/success" in path:
                    self.current_state = AuthState.COMPLETE
                    self.state_entered_at = datetime.now()
                    self.metrics['successful_auths'] += 1
                return False
            
            elif self.current_state == AuthState.COMPLETE:
                # Reset after brief delay
                if (datetime.now() - self.state_entered_at).seconds > 5:
                    self.current_state = AuthState.IDLE
                    self.state_entered_at = datetime.now()
                    self.session_data = {}
                return False
            
            # Default: don't intercept
            return False
    
    def _is_timed_out(self) -> bool:
        """Check if current session has timed out.
        
        Returns:
            True if session has exceeded timeout threshold
        """
        elapsed = (datetime.now() - self.state_entered_at).seconds
        return elapsed > self.timeout_seconds
    
    def record_bypass_attempt(self, details: str) -> None:
        """Record a potential bypass attempt for security monitoring.
        
        Args:
            details: Description of the bypass attempt
        """
        with self._lock:
            self.metrics['bypass_attempts'] += 1
            logger.warning(f"BYPASS ATTEMPT DETECTED: {details}")


class PostmanAuthHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the Postman auth daemon.
    
    Handles incoming requests and either intercepts them for SAML
    redirection or proxies them to the upstream server.
    """
    
    # Class-level configuration (set by daemon)
    config: Dict = {}
    mode: OperationMode = OperationMode.ENFORCE
    state_machine: AuthStateMachine = None
    dns_resolver: DNSResolver = None
    
    def do_GET(self):
        """Handle GET requests."""
        self._handle_request()
    
    def do_POST(self):
        """Handle POST requests."""
        self._handle_request()
    
    def do_HEAD(self):
        """Handle HEAD requests."""
        self._handle_request()
    
    def _handle_request(self):
        """Main request handler for all HTTP methods."""
        host = self.headers.get('Host', '')
        path = self.path
        method = self.command
        
        # Log request for debugging
        logger.debug(f"{method} {host}{path}")
        
        # Check if this is a health check
        if path == '/health':
            self._handle_health_check()
            return
        
        # Check if we should intercept based on state
        should_intercept = self.state_machine.should_intercept(host, path)
        
        if self.mode == OperationMode.MONITOR:
            # Monitor mode: log but don't actually intercept
            logger.info(f"MONITOR: Would intercept: {should_intercept} for {host}{path}")
            self._proxy_to_upstream(host, path, method)
            return
        
        # Parse query parameters
        parsed_url = urllib.parse.urlparse(path)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # CRITICAL SECURITY: Must intercept /login to prevent SAML bypass
        # Direct SAML redirection avoids complex redirect chains that cause connection issues
        
        if should_intercept and parsed_url.path in ['/login', '/enterprise/login', '/enterprise/login/authchooser']:
            # This is the critical interception point for BOTH Desktop and Browser flows
            auth_challenge = query_params.get('auth_challenge', [''])[0]
            
            if self.mode == OperationMode.ENFORCE:
                # Direct redirect to SAML - handles all cases uniformly, prevents auth bypass
                self._handle_unified_saml_redirect(query_params, auth_challenge)
                return
        
        # Default: proxy to upstream
        self._proxy_to_upstream(host, path, method)
    
    def _handle_unified_saml_redirect(self, query_params: Dict, auth_challenge: str = None):
        """Handle SAML redirect for both Desktop and Browser flows uniformly.
        
        Args:
            query_params: Query parameters from the request
            auth_challenge: The auth_challenge parameter (present in Desktop flows)
        """
        if auth_challenge:
            # Desktop flow with auth_challenge
            logger.info("Desktop flow detected - redirecting to SAML with auth_challenge")
            self.state_machine.session_data['auth_challenge'] = auth_challenge
            saml_url = self._get_saml_redirect_url(auth_challenge=auth_challenge)
        else:
            # Browser flow without auth_challenge
            logger.info("Browser flow detected - redirecting to SAML with team")
            team_name = self.config.get('postman_team_name', 'postman')
            
            # Extract browser flow parameters
            continue_url = query_params.get('continue', [None])[0]
            intent = query_params.get('intent', [None])[0]
            
            saml_url = self._get_saml_redirect_url(team=team_name, continue_url=continue_url, intent=intent)
        
        # Build absolute redirect URL
        redirect_url = f"https://{self.headers.get('Host', 'identity.getpostman.com')}{saml_url}"
        
        logger.info(f"Unified SAML redirect: {redirect_url}")
        self.state_machine.metrics['saml_redirects'] += 1
        self.state_machine.transition_to(AuthState.SAML_FLOW)
        
        # Send 302 redirect
        self.send_response(302)
        self.send_header('Location', redirect_url)
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.end_headers()
    
    def _force_saml_redirect(self, auth_challenge: str):
        """Force redirect to SAML even when user tries to bypass.
        
        Args:
            auth_challenge: The auth_challenge parameter
        """
        logger.warning(f"Forcing SAML redirect for bypass attempt on {self.path}")
        
        saml_url = self._get_saml_redirect_url(auth_challenge=auth_challenge)
        redirect_url = f"https://{self.headers.get('Host', 'identity.getpostman.com')}{saml_url}"
        
        self.send_response(302)
        self.send_header('Location', redirect_url)
        self.send_header('X-Enforcement', 'SAML-Required')
        self.end_headers()
    
    def _get_saml_redirect_url(self, auth_challenge: str = None, team: str = None, 
                              continue_url: str = None, intent: str = None) -> str:
        """Generate SAML redirect URL based on IdP configuration.
        
        Unified method that handles both Desktop (with auth_challenge) and 
        Browser (with continue/intent) authentication flows.
        
        Args:
            auth_challenge: Desktop auth_challenge parameter (optional)
            team: Team name (defaults to config postman_team_name)
            continue_url: Browser continue URL (optional)
            intent: Browser intent parameter (optional)
            
        Returns:
            URL to redirect user to for SAML authentication
        """
        # Use configured team name if not provided
        if team is None:
            team = self.config['postman_team_name']
        
        # Get IdP configuration from standardized location
        idp_config = self.config.get('idp_config', {})
        idp_type = idp_config.get('idp_type', 'generic')  # Use generic as safe fallback for handler
        
        # Generate base URL based on IdP type
        if idp_type == 'okta':
            # Okta-specific SAML URL format
            tenant_id = idp_config.get('okta_tenant_id', '')
            if not tenant_id:
                logger.error("Missing okta_tenant_id in IdP configuration")
                tenant_id = 'missing-tenant-id'
            base_url = f"/sso/okta/{tenant_id}/init"
            
        elif idp_type == 'azure':
            # Azure AD SAML URL format
            tenant_id = idp_config.get('tenant_id', '')
            if not tenant_id:
                logger.error("Missing tenant_id in Azure IdP configuration")
                tenant_id = 'missing-tenant-id'
            base_url = f"/sso/azure/{tenant_id}/init"
            
        elif idp_type == 'ping':
            # PingIdentity SAML URL format
            connection_id = idp_config.get('connection_id', '')
            if not connection_id:
                logger.error("Missing connection_id in Ping IdP configuration")
                connection_id = 'missing-connection-id'
            base_url = f"/sso/ping/{connection_id}/init"
            
        else:
            # Generic SAML URL
            base_url = "/sso/saml/init"
        
        # Build query parameters
        query_params = {'team': team}
        
        # Add Desktop-specific parameters
        if auth_challenge:
            query_params['auth_challenge'] = auth_challenge
        
        # Add Browser-specific parameters  
        if continue_url:
            query_params['continue'] = continue_url
        if intent:
            query_params['intent'] = intent
        
        return f"{base_url}?{urllib.parse.urlencode(query_params)}"
    
    def _proxy_to_upstream(self, host: str, path: str, method: str):
        """Proxy request to the real upstream server.
        
        Args:
            host: The hostname
            path: The request path
            method: The HTTP method
        """
        # Get real IP address for the host
        upstream_ip = self._get_real_host(host)
        
        # Read request body if present
        content_length = self.headers.get('Content-Length')
        body = None
        if content_length:
            body = self.rfile.read(int(content_length))
        
        try:
            # For intercepted domains, use socket-level connection with SNI
            if upstream_ip != host:  # We resolved to an IP
                # Create raw socket to IP
                import socket as sock
                raw_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                raw_socket.settimeout(30)
                raw_socket.connect((upstream_ip, 443))
                
                # Wrap with SSL, setting SNI to the original hostname
                context = ssl.create_default_context()
                
                # Check if insecure upstream is allowed (for testing/debugging)
                if self.config.get('advanced', {}).get('allow_insecure_upstream', False):
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    logger.warning("Using insecure upstream connection (allow_insecure_upstream=true)")
                else:
                    context.check_hostname = True
                    context.verify_mode = ssl.CERT_REQUIRED
                
                # This is the key: server_hostname sets SNI
                ssl_socket = context.wrap_socket(raw_socket, server_hostname=host)
                
                # Build HTTP request manually
                request_line = f"{method} {path} HTTP/1.1\r\n"
                headers_str = f"Host: {host}\r\n"
                
                for key, value in self.headers.items():
                    if key.lower() not in ['connection', 'accept-encoding']:
                        headers_str += f"{key}: {value}\r\n"
                
                headers_str += "Connection: close\r\n\r\n"
                
                # Send request
                ssl_socket.send((request_line + headers_str).encode())
                if body:
                    ssl_socket.send(body)
                
                # Read response
                response_data = b""
                while True:
                    chunk = ssl_socket.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                
                ssl_socket.close()
                raw_socket.close()
                
                # Parse response
                if b'\r\n\r\n' in response_data:
                    header_data, body_data = response_data.split(b'\r\n\r\n', 1)
                else:
                    header_data = response_data
                    body_data = b""
                
                # Parse status line and headers
                lines = header_data.decode('utf-8', errors='ignore').split('\r\n')
                if lines:
                    status_line = lines[0]
                    # Parse status
                    parts = status_line.split(' ', 2)
                    if len(parts) >= 2:
                        status_code = int(parts[1])
                    else:
                        status_code = 502
                    
                    # Send response to client
                    self.send_response(status_code)
                    
                    # Parse and send headers
                    for line in lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            if key.lower() not in ['connection', 'transfer-encoding', 'content-encoding']:
                                self.send_header(key, value.strip())
                    
                    self.end_headers()
                    
                    # Send body
                    if body_data:
                        self.wfile.write(body_data)
            else:
                # Normal connection (no special handling needed)
                context = ssl.create_default_context()
                
                # Check if insecure upstream is allowed (for testing/debugging)
                if self.config.get('advanced', {}).get('allow_insecure_upstream', False):
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    logger.warning("Using insecure upstream connection (allow_insecure_upstream=true)")
                else:
                    context.check_hostname = True
                    context.verify_mode = ssl.CERT_REQUIRED
                
                conn = HTTPSConnection(host, context=context)
                
                # Prepare headers - remove encoding headers to prevent compression issues
                headers = {}
                for key, value in self.headers.items():
                    if key.lower() not in ['connection', 'accept-encoding']:
                        headers[key] = value
                headers['Host'] = host
                
                # Make request
                conn.request(method, path, body, headers)
                response = conn.getresponse()
                
                # Read response
                response_body = response.read()
                
                # Send response back to client
                self.send_response(response.status)
                
                # Copy response headers (excluding connection headers)
                for key, value in response.getheaders():
                    if key.lower() not in ['connection', 'transfer-encoding']:
                        self.send_header(key, value)
                
                self.end_headers()
                
                # Send response body
                if response_body:
                    self.wfile.write(response_body)
                
                conn.close()
        
        except Exception as e:
            logger.error(f"Upstream proxy error: {e}")
            self.send_error(502, f"Bad Gateway: {str(e)}")
    
    def _get_real_host(self, intercepted_host: str) -> str:
        """Get the real upstream host for an intercepted domain.
        
        Args:
            intercepted_host: The domain we're intercepting
            
        Returns:
            The real upstream host IP to connect to
        """
        # Use DNS resolver to get real IP, avoiding /etc/hosts
        if self.dns_resolver and intercepted_host in ['identity.getpostman.com', 'identity.postman.co']:
            return self.dns_resolver.resolve(intercepted_host)
        
        # For other hosts, return as-is
        return intercepted_host
    
    def _handle_health_check(self):
        """Handle health check endpoint for monitoring."""
        # Calculate actual uptime from daemon start time
        if hasattr(self, 'daemon') and hasattr(self.daemon, 'start_time'):
            uptime = (datetime.now() - self.daemon.start_time).total_seconds()
        else:
            # Fallback if daemon reference not available
            uptime = 0
        
        # Get IdP config from standardized location
        idp_config = self.config.get('idp_config', {})
        
        status = {
            'status': 'healthy',
            'mode': self.mode.value,
            'uptime_seconds': uptime,
            'current_state': self.state_machine.current_state.value,
            'metrics': self.state_machine.metrics,
            'config': {
                'team': self.config.get('postman_team_name'),
                'idp_type': idp_config.get('idp_type')
            }
        }
        
        response = json.dumps(status).encode('utf-8')
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)
    
    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.debug(f"{self.address_string()} - {format % args}")


class SSLHTTPServer(http.server.HTTPServer):
    """HTTPS server with SSL support."""
    
    def __init__(self, server_address, handler_class, ssl_context):
        """Initialize the HTTPS server.
        
        Args:
            server_address: Tuple of (host, port)
            handler_class: Request handler class
            ssl_context: SSL context for HTTPS
        """
        super().__init__(server_address, handler_class)
        self.socket = ssl_context.wrap_socket(self.socket, server_side=True)


class PostmanAuthDaemon:
    """Main daemon class for Postman SAML enforcement.
    
    This daemon intercepts Postman Desktop authentication requests and
    enforces SAML-only authentication according to enterprise policy.
    
    Attributes:
        config: Configuration loaded from JSON file
        mode: Current operation mode (enforce/monitor/test)
        state_machine: Authentication flow state tracker
        ssl_context: SSL context for HTTPS server
    """
    
    def __init__(self, config_path: str = "config/config.json", mode: str = "enforce"):
        """Initialize the daemon.
        
        Args:
            config_path: Path to configuration file
            mode: Operation mode (enforce/monitor/test)
        """
        self.config = self._load_config(config_path)
        self.mode = OperationMode(mode)
        
        # Get advanced settings with defaults
        advanced = self.config.get('advanced', {})
        
        # Reconfigure logging with settings from config
        log_file = advanced.get('log_file', '/var/log/postman-auth.log')
        log_max_mb = advanced.get('log_max_size_mb', 10)
        log_backups = advanced.get('log_backup_count', 5)
        
        # Reconfigure global logger with rotation settings
        global logger
        logger = setup_logging(
            log_file=log_file,
            max_bytes=log_max_mb * 1024 * 1024 if log_max_mb > 0 else 0,
            backup_count=log_backups
        )
        
        timeout = advanced.get('timeout_seconds', 30)
        oauth_timeout = advanced.get('oauth_timeout_seconds', 30)
        dns_server = advanced.get('dns_server', '8.8.8.8')
        fallback_ips = advanced.get('dns_fallback_ips', {})
        dns_resolution_method = advanced.get('dns_resolution_method', 'auto')
        
        self.state_machine = AuthStateMachine(timeout, oauth_timeout)
        self.dns_resolver = DNSResolver(dns_server, fallback_ips, dns_resolution_method)
        self.ssl_context = self._setup_ssl_context()
        self.start_time = datetime.now()
        self.server = None
        self.health_server = None
        
        # Validate configuration
        self._validate_config()
        
        # Configure the handler class with our settings
        PostmanAuthHandler.config = self.config
        PostmanAuthHandler.mode = self.mode
        PostmanAuthHandler.state_machine = self.state_machine
        PostmanAuthHandler.dns_resolver = self.dns_resolver
        PostmanAuthHandler.daemon = self  # Add reference for uptime calculation
        
        logger.info(f"Daemon initialized in {self.mode.value} mode")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                # Remove comment fields
                return {k: v for k, v in config.items() if not k.startswith('_')}
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            # Return minimal default config
            return {
                'postman_hostname': 'identity.getpostman.com',
                'postman_team_name': 'postman',
                'idp_type': 'okta'
            }
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            raise
    
    def _validate_config(self) -> None:
        """Validate configuration has required fields."""
        required_fields = ['postman_team_name', 'idp_config']
        for field in required_fields:
            if field not in self.config:
                raise ValueError(f"Missing required config field: {field}")
        
        # Validate IdP configuration structure
        idp_config = self.config['idp_config']
        if not isinstance(idp_config, dict):
            raise ValueError("idp_config must be a dictionary")
        
        if 'idp_type' not in idp_config:
            raise ValueError("Missing required field: idp_config.idp_type")
        
        idp_type = idp_config['idp_type']
        
        # Validate IdP-specific required fields
        if idp_type == 'okta':
            if not idp_config.get('okta_tenant_id'):
                raise ValueError("Missing required field for Okta: idp_config.okta_tenant_id")
        elif idp_type == 'azure':
            if not idp_config.get('tenant_id'):
                raise ValueError("Missing required field for Azure: idp_config.tenant_id")
        elif idp_type == 'ping':
            if not idp_config.get('connection_id'):
                raise ValueError("Missing required field for Ping: idp_config.connection_id")
        elif idp_type != 'generic':
            logger.warning(f"Unknown IdP type: {idp_type}. Using generic SAML handling.")
        
        # Set defaults for optional fields only
        self.config.setdefault('postman_hostname', 'identity.getpostman.com')
        self.config.setdefault('ssl_cert', 'ssl/cert.pem')
        self.config.setdefault('ssl_key', 'ssl/key.pem')
        self.config.setdefault('listen_port', 443)
        self.config.setdefault('health_check_port', 8443)
    
    def _setup_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for HTTPS server.
        
        Returns:
            Configured SSL context
        """
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        cert_path = self.config.get('ssl_cert', 'ssl/cert.pem')
        key_path = self.config.get('ssl_key', 'ssl/key.pem')
        
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            logger.error("SSL certificate or key not found")
            logger.info("Generate with: ./generate_certs.sh")
            raise FileNotFoundError("SSL files missing")
        
        ssl_context.load_cert_chain(cert_path, key_path)
        return ssl_context
    
    def start(self):
        """Start the daemon and begin listening for connections."""
        # Create HTTPS server
        server_address = ('0.0.0.0', self.config.get('listen_port', 443))
        self.server = SSLHTTPServer(server_address, PostmanAuthHandler, self.ssl_context)
        
        logger.info(f"Daemon started on port {self.config.get('listen_port', 443)}")
        
        # Start health check server in a separate thread (if configured)
        if self.config.get('health_check_port'):
            self._start_health_server()
        
        try:
            # Run the server
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Daemon stopped by user")
        finally:
            self.cleanup()
    
    def _start_health_server(self):
        """Start health check server on separate port without SSL."""
        health_port = self.config['health_check_port']
        
        class HealthHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/health':
                    # Reuse the main handler's health check logic
                    handler = PostmanAuthHandler(self.request, self.client_address, self.server)
                    handler._handle_health_check()
                else:
                    self.send_error(404)
            
            def log_message(self, format, *args):
                pass  # Suppress health check logs
        
        # Run health server in a thread
        def run_health_server():
            health_address = ('127.0.0.1', health_port)
            self.health_server = http.server.HTTPServer(health_address, HealthHandler)
            logger.info(f"Health check endpoint on port {health_port}")
            self.health_server.serve_forever()
        
        health_thread = threading.Thread(target=run_health_server, daemon=True)
        health_thread.start()
    
    def cleanup(self):
        """Clean up resources on shutdown."""
        if self.server:
            self.server.shutdown()
        if self.health_server:
            self.health_server.shutdown()
        logger.info("Daemon shutdown complete")


class HostsManager:
    """Manages dynamic modifications to /etc/hosts file.
    
    This class provides safe methods for adding and removing hosts
    entries dynamically based on authentication flow state.
    """
    
    MANAGED_MARKER = "# Managed by Postman Auth Daemon"
    
    def __init__(self, hosts_file: str = "/etc/hosts"):
        """Initialize hosts manager.
        
        Args:
            hosts_file: Path to hosts file
        """
        self.hosts_file = hosts_file
        self.backup_file = f"{hosts_file}.postman-backup"
        
        # Create backup on first use
        if not os.path.exists(self.backup_file):
            self._create_backup()
    
    def _create_backup(self) -> None:
        """Create backup of hosts file."""
        try:
            subprocess.run(['cp', self.hosts_file, self.backup_file], check=True)
            logger.info(f"Created hosts backup: {self.backup_file}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to backup hosts file: {e}")
    
    def add_entry(self, ip: str, hostname: str) -> bool:
        """Add a hosts entry.
        
        Args:
            ip: IP address to map to
            hostname: Hostname to map
            
        Returns:
            True if successful, False otherwise
        """
        entry = f"{ip} {hostname} {self.MANAGED_MARKER}"
        
        try:
            # Check if entry already exists
            with open(self.hosts_file, 'r') as f:
                if hostname in f.read():
                    logger.debug(f"Entry already exists for {hostname}")
                    return True
            
            # Add entry
            with open(self.hosts_file, 'a') as f:
                f.write(f"\n{entry}")
            
            logger.info(f"Added hosts entry: {hostname} -> {ip}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add hosts entry: {e}")
            return False
    
    def remove_entry(self, hostname: str) -> bool:
        """Remove a hosts entry.
        
        Args:
            hostname: Hostname to remove
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Read all lines
            with open(self.hosts_file, 'r') as f:
                lines = f.readlines()
            
            # Filter out lines with our hostname and marker
            filtered_lines = [
                line for line in lines
                if not (hostname in line and self.MANAGED_MARKER in line)
            ]
            
            # Write back
            with open(self.hosts_file, 'w') as f:
                f.writelines(filtered_lines)
            
            logger.info(f"Removed hosts entry for {hostname}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove hosts entry: {e}")
            return False
    
    def cleanup_all(self) -> None:
        """Remove all managed entries from hosts file."""
        try:
            # Read all lines
            with open(self.hosts_file, 'r') as f:
                lines = f.readlines()
            
            # Filter out lines with our marker
            filtered_lines = [
                line for line in lines
                if self.MANAGED_MARKER not in line
            ]
            
            # Write back
            with open(self.hosts_file, 'w') as f:
                f.writelines(filtered_lines)
            
            logger.info("Cleaned up all managed hosts entries")
        except Exception as e:
            logger.error(f"Failed to cleanup hosts entries: {e}")


# Global references for signal handler
daemon = None
hosts_manager = None


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully.
    
    Args:
        signum: Signal number
        frame: Current stack frame
    """
    logger.info(f"Received signal {signum}, shutting down...")
    
    # Clean up hosts entries if using dynamic management
    if hosts_manager:
        hosts_manager.cleanup_all()
    
    # Shutdown daemon
    if daemon:
        daemon.cleanup()
    
    sys.exit(0)


def main():
    """Main entry point for the daemon."""
    global daemon, hosts_manager
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("\n" + "="*60)
        print("⚠️  ROOT PRIVILEGES REQUIRED")
        print("="*60)
        print("\nThis daemon requires root access to:")
        print("  • Bind to port 443 (HTTPS)")
        print("  • Modify /etc/hosts (if using --dynamic-hosts)")
        print("  • Write to /var/log/postman-auth.log")
        print("\nPlease run with sudo:")
        print(f"  sudo {sys.executable} {' '.join(sys.argv)}")
        print("="*60 + "\n")
        sys.exit(1)
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='Postman SAML Enforcement Daemon')
    parser.add_argument('--config', default='config/config.json',
                       help='Path to configuration file')
    parser.add_argument('--mode', choices=['enforce', 'monitor', 'test'],
                       default='enforce',
                       help='Operation mode')
    parser.add_argument('--dynamic-hosts', action='store_true',
                       help='Enable dynamic hosts management')
    args = parser.parse_args()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize hosts manager if needed
    if args.dynamic_hosts:
        hosts_manager = HostsManager()
        # Set initial hosts entries
        hosts_manager.add_entry('127.0.0.1', 'identity.getpostman.com')
        hosts_manager.add_entry('127.0.0.1', 'identity.postman.co')
    
    try:
        # Create and start daemon
        daemon = PostmanAuthDaemon(config_path=args.config, mode=args.mode)
        daemon.start()
        
    except KeyboardInterrupt:
        logger.info("Daemon stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        # Cleanup
        if hosts_manager:
            hosts_manager.cleanup_all()
        if daemon:
            daemon.cleanup()


if __name__ == '__main__':
    main()
