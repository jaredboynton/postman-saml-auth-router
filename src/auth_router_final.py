#!/usr/bin/env python3
"""Postman SAML Enforcement Daemon for Enterprise MDM Deployment.

This daemon intercepts Postman Desktop authentication requests and enforces
SAML-only authentication by redirecting users directly to the configured
enterprise SSO provider, bypassing team selection and auth method choice.

Designed for enterprise MDM deployment with ZERO external dependencies.
Uses only Python standard library for maximum compatibility and security.

Usage:
    sudo python3 auth_router_final.py [--config config.json] [--dynamic-hosts]

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
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from enum import Enum
from http.client import HTTPSConnection
from typing import Dict, Optional, Tuple, Any, List

# Constants
BUFFER_SIZE = 4096
DEFAULT_TIMEOUT = 30
OAUTH_TIMEOUT = 30
HTTPS_PORT = 443
HEALTH_PORT = 8443
DEFAULT_DNS_SERVER = '8.8.8.8'

# Configure logging
def setup_logging(log_file=None, max_bytes=10485760, backup_count=5):
    """Set up logging with rotation support."""
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
    
    When /etc/hosts redirects domains to 127.0.0.1, we need the real IPs
    to proxy requests upstream. Uses nslookup with hardcoded fallbacks.
    """
    
    def __init__(self, dns_server: str = DEFAULT_DNS_SERVER, fallback_ips: Optional[Dict[str, str]] = None):
        self.cache: Dict[str, str] = {}
        self.dns_server = dns_server
        self.fallback_ips = fallback_ips or {}
        self._lock = threading.Lock()
    
    def resolve(self, hostname: str) -> str:
        """Resolve hostname to real IP address."""
        with self._lock:
            if hostname in self.cache:
                return self.cache[hostname]
            
            ip = self._resolve_with_nslookup(hostname)
            if ip:
                self.cache[hostname] = ip
                logger.info(f"Resolved {hostname} to {ip} via nslookup")
                return ip
            
            # Fallback to hardcoded IPs for known domains
            if not self.fallback_ips:
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
        """Resolve hostname using nslookup command."""
        try:
            result = subprocess.run(
                ['nslookup', hostname, self.dns_server],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('Address:') and not line.endswith('#53'):
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
        except (OSError, ValueError) as e:
            logger.error(f"System error in nslookup for {hostname}: {e}")
            return None

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        try:
            parts = ip.split('.')
            return (len(parts) == 4 and 
                   all(p.isdigit() and 0 <= int(p) <= 255 for p in parts))
        except:
            return False


class AuthState(Enum):
    """Authentication flow states for the state machine."""
    IDLE = "idle"
    AUTH_INIT = "auth_init"  # Initial auth request received, ready to intercept
    SAML_FLOW = "saml_flow"
    OAUTH_CONTINUATION = "oauth_continuation"




class AuthStateMachine:
    """Tracks authentication flow state for proper interception.
    
    This state machine ensures we only intercept at the right points
    in the authentication flow to avoid breaking OAuth continuation.
    
    State Machine Diagram:
    ┌─────┐    /client/login or /login  ┌───────────┐
    │IDLE │ ──────────────────────────→ │AUTH_INIT  │
    └─────┘                             └───────────┘
       ↑                                       │
       │                                       │ intercept /login
       │ timeout (30s)                         │ redirect to SAML
       │                                       ↓
       │                                ┌─────────────┐
       │                                │SAML_FLOW    │
       │                                └─────────────┘
       │                                       │
       │                                       │ /continue detected
       │                                       ↓
       │                                ┌──────────────────┐
       │                                │OAUTH_CONTINUATION│
       │                                └──────────────────┘
       │                                       │
       │ success or timeout (30s)              │
       └───────────────────────────────────────┘
    
    Critical Rules:
    - NEVER intercept during OAUTH_CONTINUATION state (breaks auth chain)
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
    
    def __init__(self, timeout_seconds: int = DEFAULT_TIMEOUT, oauth_timeout_seconds: int = OAUTH_TIMEOUT):
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
        """Transition to a new state."""
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
                logger.debug("Session data cleared on transition to IDLE")
    
    def should_intercept(self, host: str, path: str) -> bool:
        """Determine if a request should be intercepted based on current state."""
        with self._lock:
            # Check for timeout first
            if self._is_timed_out():
                logger.warning("Session timed out, resetting to IDLE")
                self.current_state = AuthState.IDLE
                self.session_data = {}
            
            # Handle IDLE state
            if self.current_state == AuthState.IDLE:
                return self._handle_idle_state(host, path)
            
            # Handle AUTH_INIT state
            if self.current_state == AuthState.AUTH_INIT:
                if host == "identity.getpostman.com" and path.startswith("/login"):
                    return True  # Intercept and redirect to SAML
                return False
            
            # Handle SAML_FLOW state
            if self.current_state == AuthState.SAML_FLOW:
                if "/continue" in path and host in ["identity.postman.co", "identity.postman.com"]:
                    self.current_state = AuthState.OAUTH_CONTINUATION
                    self.state_entered_at = datetime.now()
                return False  # Never intercept during SAML flow
            
            # Handle OAUTH_CONTINUATION state
            if self.current_state == AuthState.OAUTH_CONTINUATION:
                return self._handle_oauth_state(host, path)
            
            # Default: don't intercept
            return False
    
    def _handle_idle_state(self, host: str, path: str) -> bool:
        """Handle requests in IDLE state.
        
        Args:
            host: Request host
            path: Request path
            
        Returns:
            True if request should be intercepted
        """
        # Only interested in identity.getpostman.com auth requests
        if host != "identity.getpostman.com":
            return False
        
        # Check for auth initialization
        if not ("/client" in path or path.startswith("/login")):
            return False
        
        # Initialize auth tracking
        self.current_state = AuthState.AUTH_INIT
        self.state_entered_at = datetime.now()
        self.metrics['auth_attempts'] += 1
        
        # Desktop flow tracking
        if "/client" in path:
            self.session_data['desktop_flow_initiated'] = True
            logger.debug("Desktop flow initiated via /client/login")
            return False  # Pass through Desktop client requests
        
        # Browser flow - intercept immediately
        if path.startswith("/login"):
            return True
        
        return False
    
    def _handle_oauth_state(self, host: str, path: str) -> bool:
        """Handle requests during OAuth continuation.
        
        Args:
            host: Request host
            path: Request path
            
        Returns:
            False (never intercept during OAuth)
        """
        # Check OAuth timeout
        if (datetime.now() - self.state_entered_at).seconds > self.oauth_timeout_seconds:
            logger.info(f"OAuth continuation timeout ({self.oauth_timeout_seconds}s) - resetting to IDLE")
            self.current_state = AuthState.IDLE
            self.session_data = {}
            return False
        
        # Track gateway access
        if host == "id.gw.postman.com":
            logger.info(f"OAuth flow reached id.gw.postman.com{path} - tracking but not intercepting")
        
        # Check for successful completion
        if "/browser-auth/success" in path:
            self.current_state = AuthState.IDLE
            self.session_data = {}
            self.metrics['successful_auths'] += 1
            logger.info("Authentication completed successfully")
        
        return False  # Never intercept during OAuth
    
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
        """Main request handler - entry point for all intercepted requests.
        
        Flow:
        1. Health check bypass (/health endpoint)
        2. Bypass detection (intent=switch-account, fake auth_challenge)
        3. State machine check (should we intercept?)
        4. SAML redirect if intercepting
        5. Proxy to upstream if not intercepting
        """
        host = self.headers.get('Host', '')
        path = self.path
        method = self.command
        
        # Log request for debugging
        logger.debug(f"{method} {host}{path}")
        
        # Check if this is a health check on any host
        if path == '/health':
            self._handle_health_check()
            return
        
        # Parse query parameters
        parsed_url = urllib.parse.urlparse(path)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Check for bypass attempts BEFORE state machine logic
        if host == "identity.getpostman.com" and parsed_url.path.startswith('/login'):
            if self._is_bypass_attempt(query_params):
                logger.warning(f"BYPASS ATTEMPT BLOCKED: {self.path}")
                self.state_machine.record_bypass_attempt(f"Blocked: {query_params}")
                
                # Force clean SAML redirect without dangerous params
                clean_params = {}
                if 'continue' in query_params:
                    continue_url = query_params['continue'][0] if query_params['continue'] else ''
                    if self._is_safe_continue_url(continue_url):
                        clean_params['continue'] = [continue_url]
                
                # NEVER pass auth_challenge from a bypass attempt
                self._handle_unified_saml_redirect(clean_params, None)
                return
        
        # Check if we should intercept based on state
        should_intercept = self.state_machine.should_intercept(host, path)
        
        # CRITICAL SECURITY: Must intercept /login to prevent SAML bypass
        # Direct SAML redirection avoids complex redirect chains that cause connection issues
        if should_intercept and parsed_url.path in ['/login', '/enterprise/login', '/enterprise/login/authchooser']:
            auth_challenge = query_params.get('auth_challenge', [''])[0]
            self._handle_unified_saml_redirect(query_params, auth_challenge)
            return
        
        self._proxy_to_upstream(host, path, method)
    
    def _is_bypass_attempt(self, query_params: Dict) -> bool:
        """Detect known bypass patterns in query parameters.
        
        Args:
            query_params: Parsed query parameters from the request
            
        Returns:
            True if bypass attempt detected, False otherwise
        """
        # Block account switching attempts
        if query_params.get('intent', [''])[0] == 'switch-account':
            logger.warning("Bypass attempt detected: intent=switch-account")
            return True
        
        # Block direct team selection without auth_challenge (Desktop flow marker)
        if 'target_team' in query_params and 'auth_challenge' not in query_params:
            logger.warning("Bypass attempt detected: target_team without auth_challenge")
            return True
        
        # CRITICAL: Block auth_challenge if no Desktop flow in progress
        # Legitimate Desktop flows MUST start with /client/login which sets desktop_flow_initiated
        # Any auth_challenge without prior /client/login is a bypass attempt
        if 'auth_challenge' in query_params:
            # Check if this is part of a legitimate Desktop flow
            desktop_flow_initiated = self.state_machine.session_data.get('desktop_flow_initiated', False)
            
            if not desktop_flow_initiated:
                auth_challenge_preview = query_params['auth_challenge'][0][:20] if query_params['auth_challenge'] else 'empty'
                logger.warning(f"Bypass attempt detected: auth_challenge without prior /client/login (challenge: {auth_challenge_preview}...)")
                return True
        
        # Block suspicious parameter combinations
        if 'force_auth' in query_params or 'skip_saml' in query_params:
            logger.warning(f"Bypass attempt detected: suspicious params {list(query_params.keys())}")
            return True
        
        return False
    
    def _sanitize_login_params(self, query_params: Dict) -> Dict:
        """Remove potentially dangerous parameters from login requests.
        
        Only preserves parameters that are known to be safe and necessary
        for the authentication flow.
        
        Args:
            query_params: Raw query parameters from the request
            
        Returns:
            Sanitized parameters safe for SAML redirect
        """
        safe_params = {}
        
        # Desktop flow: preserve auth_challenge
        if 'auth_challenge' in query_params:
            safe_params['auth_challenge'] = query_params['auth_challenge']
            logger.debug("Preserved auth_challenge for Desktop flow")
        
        # Browser flow: validate and preserve continue URL if safe
        if 'continue' in query_params:
            continue_url = query_params['continue'][0] if query_params['continue'] else ''
            if self._is_safe_continue_url(continue_url):
                safe_params['continue'] = [continue_url]
                logger.debug(f"Preserved safe continue URL: {continue_url}")
            else:
                logger.warning(f"Blocked unsafe continue URL: {continue_url}")
        
        # Log any parameters that were stripped
        stripped_params = set(query_params.keys()) - set(safe_params.keys())
        if stripped_params:
            logger.info(f"Stripped potentially dangerous parameters: {stripped_params}")
        
        return safe_params
    
    def _is_safe_continue_url(self, url: str) -> bool:
        """Validate that continue URL is safe and points to Postman domains.
        
        Args:
            url: The continue URL to validate
            
        Returns:
            True if URL is safe to use, False otherwise
        """
        if not url:
            return False
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Only allow HTTPS
            if parsed.scheme != 'https':
                logger.warning(f"Blocked non-HTTPS continue URL: {url}")
                return False
            
            # Only allow Postman domains
            allowed_domains = [
                'postman.co',
                'postman.com', 
                'getpostman.com',
                'go.postman.co',
                'app.postman.com',
                'identity.postman.com',
                'identity.postman.co',
                'identity.getpostman.com'
            ]
            
            # Check if hostname ends with any allowed domain
            hostname = parsed.netloc.lower()
            is_allowed = any(
                hostname == domain or hostname.endswith('.' + domain) 
                for domain in allowed_domains
            )
            
            if not is_allowed:
                logger.warning(f"Blocked continue URL to non-Postman domain: {hostname}")
            
            return is_allowed
            
        except (ValueError, AttributeError) as e:
            logger.error(f"Error validating continue URL: {e}")
            return False
    
    def _handle_unified_saml_redirect(self, query_params: Dict, auth_challenge: str = None):
        """Handle SAML redirect for both Desktop and Browser flows uniformly.
        
        Args:
            query_params: Query parameters from the request
            auth_challenge: The auth_challenge parameter (present in Desktop flows)
        """
        # Sanitize parameters to prevent bypass attempts
        clean_params = self._sanitize_login_params(query_params)
        
        if auth_challenge:
            # Desktop flow with auth_challenge
            logger.info("Desktop flow detected - redirecting to SAML with auth_challenge")
            self.state_machine.session_data['auth_challenge'] = auth_challenge
            saml_url = self._get_saml_redirect_url(auth_challenge=auth_challenge)
        else:
            # Browser flow without auth_challenge
            logger.info("Browser flow detected - redirecting to SAML with team")
            team_name = self.config.get('postman_team_name', 'postman')
            
            # Use sanitized parameters only - never pass 'intent' or 'target_team'
            continue_url = clean_params.get('continue', [None])[0]
            
            # CRITICAL: Never pass 'intent' parameter to prevent bypass
            saml_url = self._get_saml_redirect_url(team=team_name, continue_url=continue_url)
        
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
                              continue_url: str = None) -> str:
        """Generate SAML redirect URL based on IdP configuration.
        
        Unified method that handles both Desktop (with auth_challenge) and 
        Browser (with continue URL) authentication flows.
        
        SECURITY: The 'intent' parameter is explicitly NOT supported to prevent
        bypass attempts via account switching.
        
        Args:
            auth_challenge: Desktop auth_challenge parameter (optional)
            team: Team name (defaults to config postman_team_name)
            continue_url: Browser continue URL (optional, must be validated)
            
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
        
        # Add Browser-specific parameters (validated continue URL only)
        if continue_url:
            query_params['continue'] = continue_url
        
        # CRITICAL: Never add 'intent' or 'target_team' parameters
        # These can be used to bypass SAML enforcement
        
        return f"{base_url}?{urllib.parse.urlencode(query_params)}"
    
    def _get_upstream_ssl_context(self):
        """Get SSL context for upstream connections."""
        context = ssl.create_default_context()
        if self.config.get('advanced', {}).get('allow_insecure_upstream', False):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logger.warning("Using insecure upstream connection (allow_insecure_upstream=true)")
        else:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        return context
    
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
            if upstream_ip != host:  # We resolved to an IP, need manual SNI handling
                self._proxy_with_sni(host, upstream_ip, path, method, body)
            else:
                self._proxy_direct(host, path, method, body)
        
        except (ConnectionError, TimeoutError, ssl.SSLError) as e:
            logger.error(f"Upstream proxy error: {e}")
            self.send_error(502, f"Bad Gateway: {str(e)}")
    
    def _proxy_with_sni(self, host: str, upstream_ip: str, path: str, method: str, body: bytes):
        """Proxy with manual SNI handling for intercepted domains.
        
        Args:
            host: Original hostname for SNI
            upstream_ip: Resolved IP address
            path: Request path
            method: HTTP method
            body: Request body
        """
        try:
            # Create raw socket to IP
            import socket as sock
            raw_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
            raw_socket.settimeout(DEFAULT_TIMEOUT)
            raw_socket.connect((upstream_ip, 443))
            
            # Wrap with SSL, setting SNI to the original hostname
            context = self._get_upstream_ssl_context()
            
            # CRITICAL: server_hostname sets SNI for Cloudflare routing
            # Without this, Cloudflare returns 525 SSL handshake failed
            ssl_socket = context.wrap_socket(raw_socket, server_hostname=host)
            
            # Build and send request
            request_data = self._build_request(method, path, host, body)
            ssl_socket.send(request_data)
            
            # Read response
            response_data = b""
            while True:
                chunk = ssl_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                response_data += chunk
            
            ssl_socket.close()
            raw_socket.close()
            
            # Parse and send response
            self._send_parsed_response(response_data)
            
        except (socket.error, ssl.SSLError, ConnectionError) as e:
            logger.error(f"SNI proxy error: {e}")
            raise
    
    def _proxy_direct(self, host: str, path: str, method: str, body: bytes):
        """Direct proxy connection without SNI handling.
        
        Args:
            host: Hostname
            path: Request path
            method: HTTP method
            body: Request body
        """
        try:
            # Normal connection (no special handling needed)
            context = self._get_upstream_ssl_context()
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
            
        except (ConnectionError, TimeoutError, ssl.SSLError) as e:
            logger.error(f"Direct proxy error: {e}")
            raise
    
    def _build_request(self, method: str, path: str, host: str, body: bytes) -> bytes:
        """Build HTTP request data.
        
        Args:
            method: HTTP method
            path: Request path
            host: Host header value
            body: Request body
            
        Returns:
            Complete request as bytes
        """
        request_line = f"{method} {path} HTTP/1.1\r\n"
        headers_str = f"Host: {host}\r\n"
        
        for key, value in self.headers.items():
            if key.lower() not in ['connection', 'accept-encoding']:
                headers_str += f"{key}: {value}\r\n"
        
        headers_str += "Connection: close\r\n\r\n"
        
        request_data = (request_line + headers_str).encode()
        if body:
            request_data += body
        
        return request_data
    
    def _send_parsed_response(self, response_data: bytes):
        """Parse and send HTTP response to client.
        
        Args:
            response_data: Raw response bytes
        """
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
    
    # Class attributes for signal handling
    _instance = None
    _hosts_manager = None
    
    def __init__(self, config_path: str = "config/config.json"):
        """Initialize the daemon.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        
        # Get advanced settings with defaults
        advanced = self.config.get('advanced', {})
        
        timeout = advanced.get('timeout_seconds', DEFAULT_TIMEOUT)
        oauth_timeout = advanced.get('oauth_timeout_seconds', OAUTH_TIMEOUT)
        dns_server = advanced.get('dns_server', DEFAULT_DNS_SERVER)
        fallback_ips = advanced.get('dns_fallback_ips', {})
        
        self.state_machine = AuthStateMachine(timeout, oauth_timeout)
        self.dns_resolver = DNSResolver(dns_server, fallback_ips)
        self.ssl_context = self._setup_ssl_context()
        self.start_time = datetime.now()
        self.server = None
        
        # Set class instance for signal handler
        PostmanAuthDaemon._instance = self
        
        # Validate configuration
        self._validate_config()
        
        # Configure the handler class with our settings
        PostmanAuthHandler.config = self.config
        PostmanAuthHandler.state_machine = self.state_machine
        PostmanAuthHandler.dns_resolver = self.dns_resolver
        PostmanAuthHandler.daemon = self  # Add reference for uptime calculation
        
        logger.info("Daemon initialized in enforce mode")
    
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
        self.config.setdefault('listen_port', HTTPS_PORT)
        self.config.setdefault('health_check_port', HEALTH_PORT)
    
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
        server_address = ('0.0.0.0', self.config.get('listen_port', HTTPS_PORT))
        self.server = SSLHTTPServer(server_address, PostmanAuthHandler, self.ssl_context)
        
        logger.info(f"Daemon started on port {self.config.get('listen_port', HTTPS_PORT)}")
        logger.info(f"Health endpoint available at https://localhost:{self.config.get('listen_port', HTTPS_PORT)}/health")
        
        try:
            # Run the server
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Daemon stopped by user")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up resources on shutdown."""
        if self.server:
            self.server.shutdown()
        logger.info("Daemon shutdown complete")


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully.
    
    Args:
        signum: Signal number
        frame: Current stack frame
    """
    logger.info(f"Received signal {signum}, shutting down...")
    
    # Clean up hosts entries if using dynamic management
    if PostmanAuthDaemon._hosts_manager:
        PostmanAuthDaemon._hosts_manager.cleanup_all()
    
    # Shutdown daemon
    if PostmanAuthDaemon._instance:
        PostmanAuthDaemon._instance.cleanup()
    
    sys.exit(0)


def main():
    """Main entry point for the daemon."""
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("\n" + "="*60)
        print("⚠️  ROOT PRIVILEGES REQUIRED")
        print("="*60)
        print("\nThis daemon requires root access to:")
        print(f"  • Bind to port {HTTPS_PORT} (HTTPS)")
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
    parser.add_argument('--dynamic-hosts', action='store_true',
                       help='Enable dynamic hosts management')
    args = parser.parse_args()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize hosts manager if needed
    if args.dynamic_hosts:
        # Import only when needed to keep main daemon lightweight
        from dynamic_hosts.hosts_manager import HostsManager
        PostmanAuthDaemon._hosts_manager = HostsManager()
        # Set initial hosts entries
        PostmanAuthDaemon._hosts_manager.add_entry('127.0.0.1', 'identity.getpostman.com')
        PostmanAuthDaemon._hosts_manager.add_entry('127.0.0.1', 'identity.postman.co')
    
    try:
        # Create and start daemon
        daemon = PostmanAuthDaemon(config_path=args.config)
        daemon.start()
        
    except KeyboardInterrupt:
        logger.info("Daemon stopped by user")
    except (KeyboardInterrupt, SystemExit):
        raise
    except (OSError, ValueError) as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        # Cleanup
        if PostmanAuthDaemon._hosts_manager:
            PostmanAuthDaemon._hosts_manager.cleanup_all()
        if PostmanAuthDaemon._instance:
            PostmanAuthDaemon._instance.cleanup()


if __name__ == '__main__':
    main()
