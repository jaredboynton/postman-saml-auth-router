#!/usr/bin/env python3
"""
Postman SAML Proxy Daemon - PAC File Approach

This daemon operates as an HTTP proxy that intercepts traffic routed via PAC file,
terminates SSL, and redirects authentication requests to SAML IdP.

UNTESTED POC - Requires extensive validation before production use.

Usage:
    python3 saml_proxy_daemon.py [--config config.json]
"""

import http.server
import json
import logging
import os
import signal
import socket
import ssl
import sys
import threading
import urllib.parse
import urllib.request
from datetime import datetime
from http.client import HTTPSConnection
from typing import Dict, Optional, Tuple

# Configure logging
def setup_logging():
    """Set up simple logging to console and file."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('/var/log/postman-proxy.log', mode='a')
        ] if os.access('/var/log', os.W_OK) else [logging.StreamHandler()]
    )
    return logging.getLogger('postman-proxy')

logger = setup_logging()

class ProxyHTTPHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP Proxy handler that processes CONNECT requests and terminates SSL
    for identity.getpostman.com to inspect paths and redirect to SAML.
    
    UNTESTED POC - Handle with extreme caution.
    """
    
    # Class-level configuration
    config: Dict = {}
    
    def do_CONNECT(self):
        """Handle HTTP CONNECT method for HTTPS tunneling."""
        logger.debug(f"CONNECT request: {self.path}")
        
        # Parse target host and port
        try:
            host, port = self.path.split(':')
            port = int(port)
        except ValueError:
            self.send_error(400, "Bad CONNECT request")
            return
        
        # Only handle identity.getpostman.com 
        if host == "identity.getpostman.com" and port == 443:
            logger.info(f"Intercepting CONNECT to {host}:{port}")
            self._handle_saml_connect(host, port)
        else:
            logger.debug(f"Proxying CONNECT to {host}:{port}")
            self._handle_direct_connect(host, port)
    
    def _handle_saml_connect(self, host: str, port: int):
        """
        Handle CONNECT to identity.getpostman.com - terminate SSL and inspect.
        
        CRITICAL: This is complex SSL handling - UNTESTED.
        """
        try:
            # Send 200 Connection Established
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            # Get client socket
            client_socket = self.connection
            
            # Set up SSL context for server (us acting as identity.getpostman.com)
            ssl_context = self._get_ssl_context()
            
            # Wrap client connection with SSL
            ssl_client = ssl_context.wrap_socket(
                client_socket, 
                server_side=True,
                do_handshake_on_connect=False
            )
            
            # Perform SSL handshake
            ssl_client.do_handshake()
            logger.info("SSL handshake completed with client")
            
            # Now handle HTTPS requests through this SSL connection
            self._handle_ssl_requests(ssl_client, host)
            
        except Exception as e:
            logger.error(f"Error in SAML CONNECT handling: {e}")
            try:
                self.send_error(502, f"Proxy error: {str(e)}")
            except:
                pass
    
    def _handle_direct_connect(self, host: str, port: int):
        """Handle direct CONNECT for non-intercepted domains."""
        try:
            # Connect to target server
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(30)
            target_socket.connect((host, port))
            
            # Send 200 Connection Established
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            # Start bidirectional forwarding
            client_socket = self.connection
            self._forward_data(client_socket, target_socket)
            
        except Exception as e:
            logger.error(f"Error in direct CONNECT: {e}")
            try:
                self.send_error(502, f"Connection failed: {str(e)}")
            except:
                pass
    
    def _handle_ssl_requests(self, ssl_socket, host: str):
        """
        Handle HTTPS requests over established SSL connection.
        
        UNTESTED: This is a complex custom HTTPS server implementation.
        """
        try:
            while True:
                # Read HTTP request from SSL socket
                request_data = b""
                while True:
                    chunk = ssl_socket.recv(4096)
                    if not chunk:
                        return
                    request_data += chunk
                    if b'\r\n\r\n' in request_data:
                        break
                
                # Parse HTTP request
                request_lines = request_data.decode('utf-8', errors='ignore').split('\r\n')
                if not request_lines:
                    continue
                
                request_line = request_lines[0]
                method, path, version = request_line.split(' ', 2)
                
                logger.info(f"SSL Request: {method} {path}")
                
                # Check if this is a SAML authentication path
                parsed_url = urllib.parse.urlparse(path)
                if self._should_intercept_path(parsed_url.path):
                    logger.info(f"Intercepting {method} {path} for SAML redirect")
                    response = self._generate_saml_redirect(parsed_url, request_lines)
                else:
                    logger.debug(f"Proxying {method} {path} to upstream")
                    response = self._proxy_to_upstream(method, path, host, request_lines)
                
                # Send response back to client
                ssl_socket.send(response)
                
        except Exception as e:
            logger.error(f"Error handling SSL requests: {e}")
        finally:
            try:
                ssl_socket.close()
            except:
                pass
    
    def _should_intercept_path(self, path: str) -> bool:
        """Check if path should be intercepted for SAML redirect."""
        intercept_paths = ['/login', '/enterprise/login', '/enterprise/login/authchooser']
        return path in intercept_paths
    
    def _generate_saml_redirect(self, parsed_url, request_lines: list) -> bytes:
        """Generate SAML redirect response."""
        try:
            # Parse query parameters
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Generate SAML URL (same logic as original daemon)
            saml_url = self._get_saml_redirect_url(query_params)
            
            # Create redirect response
            response = f"""HTTP/1.1 302 Found\r
Location: {saml_url}\r
Cache-Control: no-cache, no-store, must-revalidate\r
Content-Length: 0\r
Connection: close\r
\r
"""
            return response.encode('utf-8')
            
        except Exception as e:
            logger.error(f"Error generating SAML redirect: {e}")
            error_response = f"""HTTP/1.1 500 Internal Server Error\r
Content-Length: 0\r
Connection: close\r
\r
"""
            return error_response.encode('utf-8')
    
    def _get_saml_redirect_url(self, query_params: Dict) -> str:
        """Generate SAML redirect URL (same logic as original daemon)."""
        # Use configured SAML init URL directly
        base_saml_url = self.config.get('saml_init_url', 'https://identity.getpostman.com/sso/saml/init')
        team_name = self.config.get('postman_team_name', 'postman')
        
        # Build query parameters
        new_params = {'team': team_name}
        
        # Add auth_challenge if present (Desktop flow)
        auth_challenge = query_params.get('auth_challenge', [''])[0]
        if auth_challenge:
            new_params['auth_challenge'] = auth_challenge
        
        # Add continue URL if present (Browser flow)
        continue_url = query_params.get('continue', [None])[0]
        if continue_url:
            new_params['continue'] = continue_url
        
        # Construct final URL
        parsed_url = urllib.parse.urlparse(base_saml_url)
        query_string = urllib.parse.urlencode(new_params)
        
        # Combine existing query params with new ones
        if parsed_url.query:
            combined_query = f"{parsed_url.query}&{query_string}"
        else:
            combined_query = query_string
        
        return urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            combined_query,
            parsed_url.fragment
        ))
    
    def _proxy_to_upstream(self, method: str, path: str, host: str, request_lines: list) -> bytes:
        """Proxy request to upstream server (simplified implementation)."""
        try:
            # This is a simplified implementation - UNTESTED
            error_response = f"""HTTP/1.1 502 Bad Gateway\r
Content-Type: text/plain\r
Content-Length: 47\r
Connection: close\r
\r
Upstream proxying not implemented in this POC"""
            return error_response.encode('utf-8')
            
        except Exception as e:
            logger.error(f"Error proxying to upstream: {e}")
            error_response = f"""HTTP/1.1 502 Bad Gateway\r
Content-Length: 0\r
Connection: close\r
\r
"""
            return error_response.encode('utf-8')
    
    def _get_ssl_context(self) -> ssl.SSLContext:
        """Get SSL context for terminating client connections."""
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        cert_path = self.config.get('ssl_cert', 'ssl/cert.pem')
        key_path = self.config.get('ssl_key', 'ssl/key.pem')
        
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            raise FileNotFoundError("SSL certificate or key not found")
        
        ssl_context.load_cert_chain(cert_path, key_path)
        return ssl_context
    
    def _forward_data(self, client_socket, target_socket):
        """Bidirectional data forwarding for direct connections."""
        def forward(source, destination):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    destination.send(data)
            except:
                pass
            finally:
                try:
                    source.close()
                    destination.close()
                except:
                    pass
        
        # Start forwarding in both directions
        client_to_target = threading.Thread(target=forward, args=(client_socket, target_socket))
        target_to_client = threading.Thread(target=forward, args=(target_socket, client_socket))
        
        client_to_target.daemon = True
        target_to_client.daemon = True
        
        client_to_target.start()
        target_to_client.start()
        
        # Wait for connections to close
        client_to_target.join()
        target_to_client.join()
    
    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.debug(f"{self.address_string()} - {format % args}")

class ProxyDaemon:
    """
    Main proxy daemon class.
    
    UNTESTED POC - Extensive validation required.
    """
    
    def __init__(self, config_path: str = "config/config.json.template"):
        """Initialize proxy daemon."""
        self.config = self._load_config(config_path)
        self.server = None
        
        # Configure handler class
        ProxyHTTPHandler.config = self.config
        
        logger.info("Proxy daemon initialized")
        logger.warning("UNTESTED POC - Use with extreme caution")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            return {
                'postman_team_name': 'postman',
                'saml_init_url': 'https://identity.getpostman.com/sso/saml/init',
                'listen_port': 8444
            }
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            raise
    
    def start(self):
        """Start the proxy daemon."""
        port = self.config.get('listen_port', 8444)
        
        logger.info(f"Starting proxy daemon on port {port}")
        logger.warning("UNTESTED POC - Monitor for issues")
        
        try:
            self.server = http.server.HTTPServer(('127.0.0.1', port), ProxyHTTPHandler)
            logger.info(f"Proxy daemon listening on 127.0.0.1:{port}")
            
            self.server.serve_forever()
            
        except KeyboardInterrupt:
            logger.info("Proxy daemon stopped by user")
        except Exception as e:
            logger.error(f"Proxy daemon error: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up resources."""
        if self.server:
            self.server.shutdown()
        logger.info("Proxy daemon cleanup complete")

def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == '--config':
        config_path = sys.argv[2] if len(sys.argv) > 2 else "config/config.json.template"
    else:
        config_path = "config/config.json.template"
    
    print("=" * 60)
    print("Postman SAML Proxy Daemon - PAC Approach")
    print("UNTESTED POC - Requires extensive validation")
    print("=" * 60)
    
    try:
        daemon = ProxyDaemon(config_path)
        daemon.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()