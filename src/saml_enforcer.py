#!/usr/bin/env python3
"""Postman SAML Enforcement Daemon for Enterprise MDM Deployment.

This daemon intercepts Postman Desktop authentication requests and enforces
SAML-only authentication by redirecting users directly to the configured
enterprise SSO provider, bypassing team selection and auth method choice.

Usage:
    sudo python3 saml_enforcer.py
"""

import http.server
import json
import logging
import os
import socket
import ssl
import sys
import urllib.parse
import urllib.request

# Constants
HTTPS_PORT = 443
DEFAULT_TIMEOUT = 30

# Configure logging
def setup_logging():
    """Set up simple console logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger('postman-auth')

logger = setup_logging()


def resolve_real_ip(hostname, dns_servers=None):
    """Resolve hostname to real IP address bypassing /etc/hosts."""
    if dns_servers is None:
        dns_servers = ['8.8.8.8', '1.1.1.1']  # Default fallback servers
    
    import subprocess
    
    # Try each DNS server in order
    for dns_server in dns_servers:
        try:
            result = subprocess.run(
                ['nslookup', hostname, dns_server],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('Address:') and not line.endswith('#53'):
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            ip = parts[1].strip()
                            logger.debug(f"Resolved {hostname} to {ip} via {dns_server}")
                            return ip
            
        except Exception as e:
            logger.debug(f"DNS resolution via {dns_server} failed for {hostname}: {e}")
            continue
    
    # If all DNS servers fail, raise an error instead of using hardcoded fallback
    logger.error(f"DNS resolution failed for {hostname} on all servers: {dns_servers}")
    raise RuntimeError(f"Unable to resolve {hostname} - check network connectivity")


class PostmanAuthHandler(http.server.BaseHTTPRequestHandler):
    """
    Handles incoming requests and either intercepts them for SAML
    redirection or proxies them to the upstream server.
    """
    
    # Class-level configuration (set by daemon)
    config = {}
    
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
        # Strip trailing slash for consistent matching
        clean_path = parsed_url.path.rstrip('/')
        intercept_paths = ['/login', '/enterprise/login', '/enterprise/login/authchooser']
        if (host == "identity.getpostman.com" and clean_path in intercept_paths):
            
            # Redirect to SAML authentication
            auth_challenge = query_params.get('auth_challenge', [''])[0]
            logger.info(f"Intercepting {method} {host}{path} - redirecting to SAML")
            self._handle_saml_redirect(query_params, auth_challenge)
            return
        
        # Everything else passes through to upstream
        logger.debug(f"Passing through {method} {host}{path}")
        self._proxy_to_upstream(host, path, method)
    
    def _handle_saml_redirect(self, query_params, auth_challenge=None):
        """Handle SAML redirect for both Postman desktop and web flows uniformly."""
        if auth_challenge:
            # Postman desktop flow with auth_challenge
            logger.info("Postman desktop flow detected - redirecting to SAML with auth_challenge")
            saml_url = self._get_saml_redirect_url(auth_challenge=auth_challenge)
        else:
            # Postman web flow without auth_challenge
            logger.info("Postman web flow detected - redirecting to SAML with team")
            team_name = self.config.get('postman_team_name', 'postman')
            continue_url = query_params.get('continue', [None])[0]
            saml_url = self._get_saml_redirect_url(team=team_name, continue_url=continue_url)
        
        logger.info(f"SAML redirect: {saml_url}")
        
        # Send 302 redirect
        self.send_response(302)
        self.send_header('Location', saml_url)
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.end_headers()
    
    def _get_saml_redirect_url(self, auth_challenge=None, team=None, continue_url=None):
        """Generate SAML redirect URL based on IdP configuration."""
        # Use configured team name if not provided
        if team is None:
            team = self.config['postman_team_name']
        
        # Use configured SAML init URL directly
        base_saml_url = self.config.get('saml_init_url', 'https://identity.getpostman.com/sso/saml/init')
        
        # Build query parameters
        query_params = {'team': team}
        
        # Add Postman desktop-specific parameters
        if auth_challenge:
            query_params['auth_challenge'] = auth_challenge
        
        # Add Postman web-specific parameters
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
    
    def _proxy_to_upstream(self, host, path, method):
        """Proxy request to the real upstream server using urllib with proper SNI."""
        # Only identity.getpostman.com is intercepted (in /etc/hosts)
        if host != 'identity.getpostman.com':
            logger.warning(f"Unexpected host in proxy: {host}")
            self.send_error(502, "Bad Gateway")
            return
        
        # Get real IP address for the host
        dns_servers = self.config.get('dns_servers', ['8.8.8.8', '1.1.1.1'])
        try:
            upstream_ip = resolve_real_ip(host, dns_servers)
        except RuntimeError as e:
            logger.error(f"DNS resolution failed: {e}")
            self.send_error(502, "Bad Gateway")
            return
        
        # Read request body if present
        content_length = self.headers.get('Content-Length')
        body = None
        if content_length:
            body = self.rfile.read(int(content_length))
        
        try:
            # Manual SNI handling for proper SSL/TLS handshake with CDN
            response_data = self._proxy_with_sni(upstream_ip, host, path, method, body)
            self.wfile.write(response_data)
            
        except Exception as e:
            logger.error(f"Upstream proxy error: {e}")
            self.send_error(502, "Bad Gateway")
    
    def _proxy_with_sni(self, upstream_ip, host, path, method, body):
        """Proxy with manual SNI handling for proper SSL handshake with CDN."""
        # Build the HTTP request manually
        request_lines = [f"{method} {path} HTTP/1.1"]
        
        # Always set Host header first (required for HTTP/1.1)
        request_lines.append(f"Host: {host}")
        
        # Copy specific headers that are safe for proxying
        safe_headers = {
            'user-agent', 'accept', 'accept-language', 'cache-control',
            'content-type', 'cookie', 'authorization', 'referer',
            'x-requested-with', 'x-forwarded-for'
        }
        
        for key, value in self.headers.items():
            key_lower = key.lower()
            # Skip problematic headers and Host (already added)
            if (key_lower not in ['connection', 'accept-encoding', 'host', 'content-length'] and
                key_lower in safe_headers):
                request_lines.append(f"{key}: {value}")
        
        # Add Connection: close for simpler handling
        request_lines.append("Connection: close")
        
        # Add body if present
        if body:
            request_lines.append(f"Content-Length: {len(body)}")
            request_lines.append("")
            request_data = "\r\n".join(request_lines).encode() + b"\r\n" + body
        else:
            request_lines.append("")
            request_data = "\r\n".join(request_lines).encode() + b"\r\n"
        
        # Create raw socket connection to IP
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(DEFAULT_TIMEOUT)
        raw_socket.connect((upstream_ip, 443))
        
        # Wrap with SSL, setting SNI to the original hostname
        context = ssl.create_default_context()
        # CRITICAL: Set server_hostname for proper SNI
        ssl_socket = context.wrap_socket(raw_socket, server_hostname=host)
        
        try:
            # Send request
            ssl_socket.send(request_data)
            
            # Read complete response (Connection: close makes this simple)
            ssl_socket.settimeout(15)  # 15 second timeout for complete response
            response_data = b""
            
            while True:
                try:
                    chunk = ssl_socket.recv(8192)
                    if not chunk:
                        break  # Connection closed by server
                    response_data += chunk
                except socket.timeout:
                    break  # Timeout - use what we have
            
            return response_data
            
        finally:
            ssl_socket.close()
            raw_socket.close()
    
    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.debug(f"{self.address_string()} - {format % args}")


class SSLHTTPServer(http.server.HTTPServer):
    """HTTPS server with SSL support."""
    
    def __init__(self, server_address, handler_class, ssl_context):
        """Initialize the HTTPS server."""
        super().__init__(server_address, handler_class)
        self.socket = ssl_context.wrap_socket(self.socket, server_side=True)


class PostmanAuthDaemon:
    """Main daemon class for Postman SAML enforcement."""
    
    def __init__(self, config_path="config/config.json"):
        """Initialize the daemon."""
        self.config = self._load_config(config_path)
        self.ssl_context = self._setup_ssl_context()
        self.server = None
        
        # Validate configuration
        if 'postman_team_name' not in self.config:
            raise ValueError("Missing required config field: postman_team_name")
        
        # Configure the handler class with our settings
        PostmanAuthHandler.config = self.config
        
        logger.info("Daemon initialized successfully")
    
    def _load_config(self, config_path):
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                # Remove comment fields
                return {k: v for k, v in config.items() if not k.startswith('_')}
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            logger.error("Enterprise deployment requires valid configuration file")
            raise FileNotFoundError(f"Required config file missing: {config_path}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            raise
    
    def _setup_ssl_context(self):
        """Create SSL context for HTTPS server."""
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        cert_path = self.config.get('ssl_cert', 'ssl/cert.pem')
        key_path = self.config.get('ssl_key', 'ssl/key.pem')
        
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            logger.error("SSL certificate or key not found")
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


def main():
    """Main entry point for the daemon."""
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("\n" + "="*60)
        print("⚠️  ROOT PRIVILEGES REQUIRED")
        print("="*60)
        print("\nThis daemon requires root access to:")
        print(f"  • Bind to port {HTTPS_PORT} (HTTPS)")
        print("\nPlease run with sudo:")
        print(f"  sudo {sys.executable} {' '.join(sys.argv)}")
        print("="*60 + "\n")
        sys.exit(1)
    
    try:
        # Create and start daemon
        daemon = PostmanAuthDaemon()
        daemon.start()
        
    except KeyboardInterrupt:
        logger.info("Daemon stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()