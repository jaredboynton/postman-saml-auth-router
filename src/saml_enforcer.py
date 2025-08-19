#!/usr/bin/env python3
"""Postman SAML Enforcement Daemon for Enterprise MDM Deployment.

This daemon intercepts Postman Desktop authentication requests and enforces
SAML-only authentication by redirecting users directly to the configured
enterprise SSO provider, bypassing team selection and auth method choice.

Usage:
    sudo python3 saml_enforcer.py [--config config.json] [--dynamic-hosts]
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
from datetime import datetime
from http.client import HTTPSConnection
from typing import Dict, Optional, Tuple

# Constants
BUFFER_SIZE = 4096
DEFAULT_TIMEOUT = 30
HTTPS_PORT = 443
DEFAULT_DNS_SERVER = '8.8.8.8'

# Configure logging
def setup_logging():
    """Set up simple logging to console and file."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('/var/log/postman-auth.log', mode='a')
        ] if os.access('/var/log', os.W_OK) else [logging.StreamHandler()]
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
            
            # Fallback to configured IPs or last resort defaults
            if not self.fallback_ips:
                # These are Cloudflare IPs as of deployment - should be overridden in config
                logger.warning("Using default fallback IPs - configure dns_fallback_ips in config for production")
                self.fallback_ips = {
                    'identity.getpostman.com': '104.18.36.161'
                }
            
            ip = self.fallback_ips.get(hostname)
            if not ip:
                logger.error(f"No fallback IP configured for {hostname}")
                # Return localhost to fail safely rather than crash
                ip = '127.0.0.1'
            self.cache[hostname] = ip
            logger.warning(f"Using fallback IP for {hostname}: {ip}")
            return ip

    def _resolve_with_nslookup(self, hostname: str) -> Optional[str]:
        """Resolve hostname using multiple methods in order of preference."""
        # Try DNS-over-HTTPS first for better security and reliability
        ip = self._resolve_with_doh(hostname)
        if ip:
            return ip
        
        # Fallback to traditional nslookup
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
    
    def _resolve_with_doh(self, hostname: str) -> Optional[str]:
        """Resolve hostname using DNS-over-HTTPS for improved security."""
        try:
            # Use Cloudflare's DNS-over-HTTPS service
            url = f"https://cloudflare-dns.com/dns-query?name={hostname}&type=A"
            req = urllib.request.Request(
                url,
                headers={
                    'Accept': 'application/dns-json',
                    'User-Agent': 'PostmanAuthDaemon/2.0'
                }
            )
            
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode())
                if data.get('Answer'):
                    for answer in data['Answer']:
                        if answer.get('type') == 1:  # A record
                            ip = answer.get('data')
                            if ip and self._is_valid_ip(ip):
                                logger.debug(f"Resolved {hostname} to {ip} via DoH")
                                return ip
        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            logger.debug(f"DNS-over-HTTPS failed for {hostname}: {e}")
        except Exception as e:
            logger.debug(f"Unexpected error in DoH resolution for {hostname}: {e}")
        
        return None

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        try:
            parts = ip.split('.')
            return (len(parts) == 4 and 
                   all(p.isdigit() and 0 <= int(p) <= 255 for p in parts))
        except:
            return False

class PostmanAuthHandler(http.server.BaseHTTPRequestHandler):
    """
    Handles incoming requests and either intercepts them for SAML
    redirection or proxies them to the upstream server.
    """
    
    # Class-level configuration (set by daemon)
    config: Dict = {}
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
        """
        Simple logic:
        1. If identity.getpostman.com + /login -> redirect to SAML
        2. Everything else -> pass through to upstream
        """
        host = self.headers.get('Host', '')
        path = self.path
        method = self.command
        
        # Log request for debugging
        logger.debug(f"{method} {host}{path}")
        
        # Parse query parameters
        parsed_url = urllib.parse.urlparse(path)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # CORE LOGIC: Only intercept /login on identity.getpostman.com for SAML enforcement
        if (host == "identity.getpostman.com" and 
            parsed_url.path in ['/login', '/enterprise/login', '/enterprise/login/authchooser']):
            
            # Redirect to SAML authentication
            auth_challenge = query_params.get('auth_challenge', [''])[0]
            logger.info(f"Intercepting {method} {host}{path} - redirecting to SAML")
            self._handle_unified_saml_redirect(query_params, auth_challenge)
            return
        
        # Everything else passes through to upstream
        logger.debug(f"Passing through {method} {host}{path}")
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
            saml_url = self._get_saml_redirect_url(auth_challenge=auth_challenge)
        else:
            # Browser flow without auth_challenge
            logger.info("Browser flow detected - redirecting to SAML with team")
            team_name = self.config.get('postman_team_name', 'postman')
            
            # Use continue URL from original params
            continue_url = query_params.get('continue', [None])[0]
            saml_url = self._get_saml_redirect_url(team=team_name, continue_url=continue_url)
        
        # saml_url is already a complete URL now
        logger.info(f"Unified SAML redirect: {saml_url}")
        
        # Send 302 redirect
        self.send_response(302)
        self.send_header('Location', saml_url)
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
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
        
        # Use configured SAML init URL directly
        base_saml_url = self.config.get('saml_init_url', 'https://identity.getpostman.com/sso/saml/init')
        
        # Security: validate hostname if it's a full URL
        try:
            parsed = urllib.parse.urlparse(base_saml_url)
            if parsed.netloc and parsed.netloc != 'identity.getpostman.com':
                logger.warning(f"SAML URL hostname should be identity.getpostman.com, got: {parsed.netloc}")
        except Exception as e:
            logger.error(f"Invalid SAML URL format: {base_saml_url} - {e}")
        
        if 'sso/saml/init' in base_saml_url:
            logger.warning("Using generic SAML URL - configure 'saml_init_url' with your specific IdP URL")
        
        # Build query parameters
        query_params = {'team': team}
        
        # Add Desktop-specific parameters
        if auth_challenge:
            query_params['auth_challenge'] = auth_challenge
        
        # Add Browser-specific parameters
        if continue_url:
            query_params['continue'] = continue_url
        
        # Add query parameters to the full URL
        parsed_url = urllib.parse.urlparse(base_saml_url)
        query_string = urllib.parse.urlencode(query_params)
        
        # Combine existing query params (if any) with new ones
        if parsed_url.query:
            combined_query = f"{parsed_url.query}&{query_string}"
        else:
            combined_query = query_string
            
        # Return the complete URL with query parameters
        return urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc, 
            parsed_url.path,
            parsed_url.params,
            combined_query,
            parsed_url.fragment
        ))
    
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
            # All intercepted requests use SNI handling since we resolve to IPs
            self._proxy_with_sni(host, upstream_ip, path, method, body)
        
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
            
            # Set SNI (Server Name Indication) for proper SSL/TLS handshake
            # Required for Cloudflare and other CDN/proxy services to route correctly
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
        # Only identity.getpostman.com is intercepted (in /etc/hosts)
        if self.dns_resolver and intercepted_host == 'identity.getpostman.com':
            return self.dns_resolver.resolve(intercepted_host)
        
        # This shouldn't happen since only intercepted domains hit our daemon
        logger.warning(f"Unexpected host in proxy: {intercepted_host}")
        return intercepted_host
    
    
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
        
        dns_server = advanced.get('dns_server', DEFAULT_DNS_SERVER)
        fallback_ips = advanced.get('dns_fallback_ips', {})
        
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
        PostmanAuthHandler.dns_resolver = self.dns_resolver
        PostmanAuthHandler.daemon = self  # Add reference for uptime calculation
        
        logger.info("Daemon initialized successfully")
    
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
                'postman_team_name': 'postman',
                'saml_init_url': 'https://identity.getpostman.com/sso/saml/init'
            }
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            raise
    
    def _validate_config(self) -> None:
        """Validate configuration has required fields."""
        required_fields = ['postman_team_name']
        for field in required_fields:
            if field not in self.config:
                raise ValueError(f"Missing required config field: {field}")
        
        # Validate SAML init URL if provided
        saml_url = self.config.get('saml_init_url')
        if saml_url:
            try:
                parsed = urllib.parse.urlparse(saml_url)
                if not parsed.path.startswith('/sso/'):
                    logger.warning(f"SAML URL path should start with /sso/: {parsed.path}")
                if parsed.netloc and parsed.netloc != 'identity.getpostman.com':
                    logger.warning(f"SAML URL should use identity.getpostman.com hostname: {parsed.netloc}")
            except Exception as e:
                logger.error(f"Invalid SAML URL format: {saml_url} - {e}")
        
        # Set defaults for optional fields only
        self.config.setdefault('ssl_cert', 'ssl/cert.pem')
        self.config.setdefault('ssl_key', 'ssl/key.pem')
        self.config.setdefault('listen_port', HTTPS_PORT)
    
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
        server_address = ('127.0.0.1', self.config.get('listen_port', HTTPS_PORT))
        self.server = SSLHTTPServer(server_address, PostmanAuthHandler, self.ssl_context)
        
        logger.info(f"Daemon started on port {self.config.get('listen_port', HTTPS_PORT)}")
        
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
