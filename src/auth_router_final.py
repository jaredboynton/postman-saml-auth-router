#!/usr/bin/env python3
"""
Final Postman Authentication Router with SAML Proxy
Properly handles SAML callbacks by proxying to real Postman servers
"""

import http.server
import socketserver
import ssl
import json
import logging
import os
import subprocess
import socket
import uuid
import base64
from urllib.parse import parse_qs, urlparse, parse_qsl, urlencode
from idp_providers import create_idp_provider

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for more detail
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PostmanAuthRouter-Final')


class DNSResolver:
    """Resolves real IPs using external DNS to bypass hosts file"""
    
    def __init__(self, dns_server='8.8.8.8'):
        self.dns_server = dns_server
        self.cache = {}
    
    def resolve(self, hostname):
        """Get real IP for hostname by querying external DNS"""
        if hostname in self.cache:
            return self.cache[hostname]
        
        try:
            # Use dig to query Google DNS directly, following CNAMEs
            result = subprocess.run(
                ['dig', f'@{self.dns_server}', hostname, 'A', '+short'],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                # Get last line which should be the IP (after CNAME resolution)
                for line in reversed(lines):
                    # Check if it's an IP address (contains dots and all parts are numbers)
                    if '.' in line and all(part.isdigit() for part in line.split('.')):
                        self.cache[hostname] = line
                        logger.info(f"Resolved {hostname} to {line}")
                        return line
        except Exception as e:
            logger.error(f"DNS resolution failed: {e}")
        
        # Fallback
        return socket.gethostbyname(hostname)


class FinalAuthRouter(http.server.BaseHTTPRequestHandler):
    """Final router with proper SAML callback handling and IDP abstraction"""
    
    # Configuration-driven values (loaded from config.json)
    OKTA_APP_ID = None
    IDP_URL = None
    POSTMAN_HOSTNAME = None
    
    # Shared DNS resolver and IDP provider
    dns_resolver = DNSResolver()
    idp_provider = None
    config = None
    
    @classmethod
    def set_config(cls, config_path):
        """Load configuration and set all values from config file"""
        with open(config_path, 'r') as f:
            cls.config = json.load(f)
        
        # Set basic values from config (works for both legacy and new configs)
        cls.OKTA_APP_ID = cls.config.get('okta_app_id', cls.OKTA_APP_ID)
        cls.IDP_URL = cls.config.get('idp_url', cls.IDP_URL)
        cls.POSTMAN_HOSTNAME = cls.config.get('postman_hostname', 'identity.getpostman.com')
        
        # Initialize IDP provider if idp_type is specified
        if 'idp_type' in cls.config:
            cls.idp_provider = create_idp_provider(cls.config)
            logger.info(f"Configured with {cls.idp_provider.get_display_name()} as IDP")
        else:
            logger.info("Using legacy Okta configuration")
    
    # Postman session cookie names
    POSTMAN_COOKIES = [
        'legacy_sails.sid',
        'pm_dvc',
        'postman.sid',
        'pm.sid',
        'workspace_session',
        'postman-session'
    ]
    
    def do_GET(self):
        # Special handling for /continue endpoint
        if '/continue' in self.path:
            self.handle_continue_endpoint()
        else:
            self.route_request()
    
    def do_POST(self):
        # Special handling for SAML callbacks
        if '/sso/okta/' in self.path.lower():
            self.handle_saml_callback()
        else:
            self.route_request()
    
    def route_request(self):
        """Route based on cookies and path"""
        client_ip = self.client_address[0]
        path = self.path
        cookie_header = self.headers.get('Cookie', '')
        
        logger.info(f"Request from {client_ip}: {self.command} {path}")
        
        # Check for Postman session cookies
        has_session = any(cookie in cookie_header for cookie in self.POSTMAN_COOKIES)
        
        if has_session:
            logger.info(f"✅ Session found - proxying to real Postman")
            self.proxy_to_postman()
        else:
            logger.info(f"❌ No session - redirecting to IDP")
            self.redirect_to_idp()
    
    def handle_saml_callback(self):
        """Proxy SAML callback POST to real Postman using curl --resolve"""
        logger.info(f"🔐 SAML callback detected: {self.path}")
        
        try:
            # Read POST body
            content_length = int(self.headers.get('Content-Length', 0))
            post_body = self.rfile.read(content_length)
            post_body_str = post_body.decode('utf-8', errors='ignore')
            
            # Parse the POST body to extract RelayState
            post_params = dict(parse_qsl(post_body_str))
            relay_state_encoded = post_params.get('RelayState', '')
            
            # Decode RelayState to get continue URL
            continue_url = ''
            session_id = ''
            if relay_state_encoded:
                try:
                    relay_state_json = base64.b64decode(relay_state_encoded).decode()
                    relay_state = json.loads(relay_state_json)
                    continue_url = relay_state.get('continue', '')
                    session_id = relay_state.get('session_id', '')
                    logger.info(f"📍 Extracted continue URL from RelayState: {continue_url}")
                    logger.info(f"📍 Session ID: {session_id}")
                except Exception as e:
                    logger.warning(f"Could not decode RelayState: {e}")
            
            # Get real Postman IP
            real_ip = self.dns_resolver.resolve(self.POSTMAN_HOSTNAME)
            
            # Don't add continue to the callback URL - Postman handles state internally
            target_path = self.path
            
            logger.info(f"→ Proxying SAML to {self.POSTMAN_HOSTNAME} via {real_ip}")
            
            # Build curl command with --resolve to bypass hosts file
            curl_cmd = [
                'curl',
                '-X', 'POST',
                '--resolve', f'{self.POSTMAN_HOSTNAME}:443:{real_ip}',
                f'https://{self.POSTMAN_HOSTNAME}{target_path}',
                '--data-raw', post_body_str,
                '-i',  # Include headers in output
                '-s',  # Silent mode
                '--compressed',
                '-k'  # Skip cert verification (like verify=False)
            ]
            
            # Add all relevant headers from the original request
            for key, value in self.headers.items():
                if key.lower() not in ['host', 'content-length', 'connection']:
                    curl_cmd.extend(['-H', f'{key}: {value}'])
            
            # Add Host header explicitly
            curl_cmd.extend(['-H', f'Host: {self.POSTMAN_HOSTNAME}'])
            
            # Execute curl
            result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                logger.error(f"curl failed: {result.stderr}")
                self.send_error(502, "SAML proxy failed")
                return
            
            # Debug: log raw response
            logger.debug(f"Raw curl output length: {len(result.stdout)}")
            logger.debug(f"First 500 chars: {result.stdout[:500]}")
            
            # Parse response (headers and body separated by double CRLF or double LF for HTTP/2)
            if '\r\n\r\n' in result.stdout:
                response_parts = result.stdout.split('\r\n\r\n', 1)
                line_sep = '\r\n'
            else:
                response_parts = result.stdout.split('\n\n', 1)
                line_sep = '\n'
            
            headers_text = response_parts[0] if response_parts else ''
            body = response_parts[1] if len(response_parts) > 1 else ''
            
            # Extract status code from first line (e.g., "HTTP/2 302")
            status_line = headers_text.split(line_sep)[0] if headers_text else 'HTTP/1.1 502'
            status_parts = status_line.split()
            status_code = int(status_parts[1]) if len(status_parts) > 1 else 502
            
            logger.info(f"← Postman responded: {status_code}")
            
            # Send response status
            self.send_response(status_code)
            
            # Parse and forward headers (especially Set-Cookie!)
            location_header = None
            import re
            for line in headers_text.split(line_sep)[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    # Skip certain headers
                    if key.lower() not in ['connection', 'transfer-encoding', 'content-encoding', 'content-length']:
                        # Special handling for Location header on redirects
                        if key.lower() == 'location' and status_code in [301, 302, 303, 307, 308]:
                            location_header = value
                            # Check if this is the /continue endpoint
                            if '/continue' in value and continue_url:
                                # Store the continue URL in our session storage
                                # For now, we'll append it to the state token in the URL
                                if 'state=' in value:
                                    # The state token tracks the session - we shouldn't modify it
                                    logger.info(f"📦 Location has state token, preserving as-is: {value}")
                                    # Store continue URL in our session storage for this state
                                    if not hasattr(self.__class__, 'session_storage'):
                                        self.__class__.session_storage = {}
                                    # Extract state from the location
                                    state_match = re.search(r'state=([^&]+)', value)
                                    if state_match:
                                        state_token = state_match.group(1)
                                        self.__class__.session_storage[state_token] = continue_url
                                        logger.info(f"💾 Stored continue URL for state {state_token[:20]}...: {continue_url}")
                                else:
                                    logger.info(f"📍 Location without state: {value}")
                        
                        self.send_header(key, value)
                        if key.lower() == 'set-cookie':
                            logger.info(f"🍪 Forwarding cookie: {value[:50]}...")
            
            # Set content length
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            
            # Send response body
            self.wfile.write(body.encode('utf-8', errors='ignore'))
            
            logger.info(f"✅ SAML response proxied successfully")
            
        except Exception as e:
            logger.error(f"❌ SAML proxy failed: {e}")
            self.send_error(502, "Failed to proxy SAML callback")
    
    def proxy_to_postman(self):
        """Proxy authenticated request to real Postman using curl --resolve"""
        try:
            # Get real IP
            real_ip = self.dns_resolver.resolve(self.POSTMAN_HOSTNAME)
            
            logger.info(f"Proxying {self.command} {self.path} to {real_ip}")
            
            # Build curl command
            curl_cmd = [
                'curl',
                '-X', self.command,
                '--resolve', f'{self.POSTMAN_HOSTNAME}:443:{real_ip}',
                f'https://{self.POSTMAN_HOSTNAME}{self.path}',
                '-i',  # Include headers
                '-s',  # Silent
                '--compressed',
                '-k'  # Skip cert verification
            ]
            
            # Add headers
            for key, value in self.headers.items():
                if key.lower() not in ['host', 'content-length', 'connection']:
                    curl_cmd.extend(['-H', f'{key}: {value}'])
            
            # For POST/PUT, add body
            if self.command in ['POST', 'PUT', 'PATCH']:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    body = self.rfile.read(content_length)
                    curl_cmd.extend(['--data-raw', body.decode('utf-8', errors='ignore')])
            
            # Execute
            result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                logger.error(f"curl failed: {result.stderr}")
                self.send_error(502, "Proxy failed")
                return
            
            # Parse response
            response_parts = result.stdout.split('\r\n\r\n', 1)
            headers_text = response_parts[0] if response_parts else ''
            body = response_parts[1] if len(response_parts) > 1 else ''
            
            # Get status code
            status_line = headers_text.split('\r\n')[0] if headers_text else 'HTTP/1.1 502'
            status_code = int(status_line.split()[1]) if len(status_line.split()) > 1 else 502
            
            # Send response
            self.send_response(status_code)
            
            # Forward headers
            for line in headers_text.split('\r\n')[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    if key.lower() not in ['connection', 'transfer-encoding', 'content-encoding', 'content-length']:
                        self.send_header(key, value)
            
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            
            # Send body
            self.wfile.write(body.encode('utf-8', errors='ignore'))
            
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            self.send_error(502, "Proxy error")
    
    def redirect_to_idp(self):
        """Redirect to IDP for authentication, preserving continue parameter"""
        # Parse query parameters from original request
        parsed_url = urlparse(self.path)
        query_params = dict(parse_qsl(parsed_url.query))
        
        # Get the continue URL if present
        continue_url = query_params.get('continue', '')
        
        # Create session ID
        session_id = f"aln{uuid.uuid4().hex[:20]}"
        
        # Store the continue URL in RelayState along with session ID
        relay_state = {
            'session_id': session_id,
            'continue': continue_url,
            'original_path': self.path  # Store full original path
        }
        
        # Encode RelayState as base64 JSON
        relay_state_json = json.dumps(relay_state)
        relay_state_encoded = base64.b64encode(relay_state_json.encode()).decode()
        
        # Build IDP URL with RelayState - use provider if available, else legacy
        if self.idp_provider:
            idp_url = self.idp_provider.get_auth_url(relay_state_encoded)
            provider_name = self.idp_provider.get_display_name()
        else:
            # Legacy hardcoded Okta URL
            idp_url = f"{self.IDP_URL}?RelayState={relay_state_encoded}"
            provider_name = "Okta (legacy)"
        
        logger.info(f"→ Redirecting to {provider_name} with RelayState containing continue URL: {continue_url}")
        
        self.send_response(302)
        self.send_header('Location', idp_url)
        self.send_header('Cache-Control', 'no-cache, no-store')
        self.end_headers()
    
    def handle_continue_endpoint(self):
        """Handle /continue endpoint to inject stored continue URL"""
        logger.info(f"🎯 Continue endpoint: {self.path}")
        
        # Extract state token from URL
        parsed_url = urlparse(self.path)
        query_params = dict(parse_qsl(parsed_url.query))
        state_token = query_params.get('state', '')
        
        # Check if we have a stored continue URL for this state
        continue_url = None
        if hasattr(self.__class__, 'session_storage') and state_token:
            continue_url = self.__class__.session_storage.get(state_token)
            if continue_url:
                logger.info(f"📦 Found stored continue URL for state {state_token[:20]}...: {continue_url}")
        
        # If we have a continue URL, redirect to it with authentication
        if continue_url and any(cookie in self.headers.get('Cookie', '') for cookie in self.POSTMAN_COOKIES):
            logger.info(f"✅ Redirecting to continue URL: {continue_url}")
            self.send_response(302)
            self.send_header('Location', continue_url)
            self.send_header('Cache-Control', 'no-cache, no-store')
            self.end_headers()
            # Clean up session storage
            if state_token in self.__class__.session_storage:
                del self.__class__.session_storage[state_token]
        else:
            # Otherwise, proxy to real Postman /continue endpoint
            logger.info(f"🔄 Proxying /continue to real Postman")
            self.proxy_to_postman()
    
    def log_message(self, format, *args):
        # Reduce console spam
        pass  # Logging handled above


def run_final_server(port=443):
    """Run the final HTTPS server with SAML proxy support"""
    logger.info("=" * 60)
    logger.info("FINAL AUTH ROUTER: Complete SAML support")
    logger.info("- DNS resolution for real IPs")
    logger.info("- SAML callback proxying")
    logger.info("- Cookie-based authentication")
    logger.info("=" * 60)
    
    # Get SSL cert paths
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cert_file = os.path.join(script_dir, 'ssl', 'cert.pem')
    key_file = os.path.join(script_dir, 'ssl', 'key.pem')
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logger.error(f"SSL certificates not found")
        return
    
    # Check hosts entry
    check_cmd = "grep 'identity.getpostman.com' /etc/hosts"
    result = subprocess.run(check_cmd, shell=True, capture_output=True)
    
    if result.returncode != 0:
        logger.warning("⚠️  Add hosts entry:")
        logger.warning("    echo '127.0.0.1 identity.getpostman.com' | sudo tee -a /etc/hosts")
    else:
        logger.info("✓ Hosts entry present")
    
    # Create HTTPS server
    httpd = socketserver.TCPServer(("127.0.0.1", port), FinalAuthRouter)
    
    # Wrap with SSL
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert_file, key_file)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    logger.info(f"Listening on https://127.0.0.1:{port}")
    logger.info("=" * 60)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        httpd.shutdown()


if __name__ == "__main__":
    import sys
    
    # Require config file
    if len(sys.argv) < 2:
        print("Usage: python3 auth_router_final.py <config.json>")
        print("Example: python3 auth_router_final.py config/config.json")
        sys.exit(1)
    
    config_file = sys.argv[1]
    
    try:
        # Always load config - no hardcoded fallbacks
        FinalAuthRouter.set_config(config_file)
        logger.info(f"Configuration loaded from: {config_file}")
        
        run_final_server()
    except FileNotFoundError:
        logger.error(f"Config file not found: {config_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        sys.exit(1)