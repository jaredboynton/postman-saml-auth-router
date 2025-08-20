#!/usr/bin/env python3
"""Postman SAML Enforcement Daemon for Enterprise MDM Deployment.

This daemon intercepts Postman Desktop authentication requests and enforces
SAML-only authentication by redirecting users directly to the configured
enterprise SSO provider, bypassing team selection and auth method choice.

Usage:
    sudo python3 saml_enforcer.py
"""

import atexit
import http.server
import json
import logging
import os
import shutil
import signal
import socket
import ssl
import sqlite3
import subprocess
import sys
import threading
import time
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
        
        # Health check endpoint for daemon monitoring
        if host == "identity.getpostman.com" and parsed_url.path == '/health':
            self._handle_health_check()
            return
            
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
    
    def _handle_health_check(self):
        """Handle health check requests."""
        logger.debug("Health check request received")
        
        # Send simple 200 OK response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.end_headers()
        
        # Send simple health status
        health_data = {
            'status': 'healthy',
            'service': 'postman-saml-enforcer',
            'timestamp': time.time()
        }
        
        response_json = json.dumps(health_data)
        self.wfile.write(response_json.encode('utf-8'))
    
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
        self._monitoring = False
        self._monitor_thread = None
        
        # Validate configuration
        if 'postman_team_name' not in self.config:
            raise ValueError("Missing required config field: postman_team_name")
        
        # Configure the handler class with our settings
        PostmanAuthHandler.config = self.config
        
        # Clean up any stale hosts entries from previous daemon instances
        self._cleanup_stale_hosts_entries()
        
        # NOTE: Postman session clearing is now handled by separate script
        # Run scripts/clear_postman_sessions.py once before starting this daemon
        
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
    
    def _remove_certificate_from_system_store(self, operation_name="certificate cleanup"):
        """Remove identity.getpostman.com certificate from system trust store.
        
        Args:
            operation_name: Description of the operation for logging purposes
        """
        logger.info(f"Performing {operation_name}")
        
        try:
            if sys.platform == "win32":
                # Windows: Remove from Trusted Root Certification Authorities
                ps_script = '''
                $certs = Get-ChildItem -Path "Cert:\\LocalMachine\\Root" | Where-Object { 
                    $_.Subject -like "*identity.getpostman.com*" -or $_.DnsNameList -like "*identity.getpostman.com*"
                }
                if ($certs) {
                    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    foreach ($cert in $certs) {
                        try {
                            $store.Remove($cert)
                            Write-Output "Removed certificate: $($cert.Subject)"
                        } catch {
                            Write-Output "Warning: Could not remove certificate $($cert.Subject)"
                        }
                    }
                    $store.Close()
                }
                '''
                
                result = subprocess.run([
                    "powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", ps_script
                ], capture_output=True, text=True, timeout=30)
                
                if result.stdout.strip():
                    logger.info(f"Certificate cleanup: {result.stdout.strip()}")
            
            else:
                # macOS/Linux: Remove from System Keychain
                try:
                    # Find and remove certificate (using -Z for detailed output)
                    result = subprocess.run([
                        'security', 'find-certificate', '-c', 'identity.getpostman.com',
                        '/Library/Keychains/System.keychain', '-Z'
                    ], capture_output=True, text=True)
                    
                    if result.returncode == 0 and "identity.getpostman.com" in result.stdout:
                        # Remove certificate by common name
                        delete_result = subprocess.run([
                            'security', 'delete-certificate', '-c', 'identity.getpostman.com',
                            '/Library/Keychains/System.keychain'
                        ], capture_output=True, text=True)
                        
                        if delete_result.returncode == 0:
                            logger.info("Removed certificate from system keychain")
                        else:
                            logger.debug(f"Certificate removal note: {delete_result.stderr}")
                
                except Exception as e:
                    logger.debug(f"Certificate cleanup note: {e}")
        
        except Exception as e:
            logger.warning(f"Certificate cleanup warning: {e}")
    
    def _cleanup_old_certificates(self):
        """Remove old/duplicate certificates from system trust store."""
        self._remove_certificate_from_system_store("old certificate cleanup")
    
    def _generate_ssl_certificate(self, cert_path, key_path):
        """Generate SSL certificate and private key."""
        logger.info("Generating SSL certificates")
        
        # Ensure certificate directory exists
        cert_dir = os.path.dirname(cert_path)
        os.makedirs(cert_dir, exist_ok=True)
        
        if sys.platform == "win32":
            # Windows: Use PowerShell PKI
            ps_script = f'''
            $cert = New-SelfSignedCertificate -DnsName "identity.getpostman.com", "localhost", "127.0.0.1" -CertStoreLocation "cert:\\LocalMachine\\My" -KeyLength 2048 -KeyAlgorithm RSA -KeyExportPolicy Exportable -KeyUsage DigitalSignature, KeyEncipherment -Type SSLServerAuthentication
            
            $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            
            $certPem = "-----BEGIN CERTIFICATE-----`n" + [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks) + "`n-----END CERTIFICATE-----"
            $privateKeyPem = "-----BEGIN PRIVATE KEY-----`n" + [System.Convert]::ToBase64String($privateKey.ExportPkcs8PrivateKey(), [System.Base64FormattingOptions]::InsertLineBreaks) + "`n-----END PRIVATE KEY-----"
            
            Set-Content -Path "{cert_path}" -Value $certPem
            Set-Content -Path "{key_path}" -Value $privateKeyPem
            '''
            
            result = subprocess.run([
                "powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", ps_script
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                raise RuntimeError(f"Certificate generation failed: {result.stderr}")
        
        else:
            # macOS/Linux: Use OpenSSL
            cert_conf_path = os.path.join(cert_dir, "cert.conf")
            
            # Create certificate configuration if it doesn't exist
            if not os.path.exists(cert_conf_path):
                cert_conf_content = """[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = identity.getpostman.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = identity.getpostman.com
DNS.2 = localhost
IP.1 = 127.0.0.1
"""
                with open(cert_conf_path, 'w') as f:
                    f.write(cert_conf_content)
                logger.info("Created certificate configuration")
            
            # Generate certificate with OpenSSL
            result = subprocess.run([
                'openssl', 'req', '-new', '-x509', '-days', '365', '-nodes',
                '-out', cert_path,
                '-keyout', key_path,
                '-config', cert_conf_path,
                '-extensions', 'v3_req'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                raise RuntimeError(f"Certificate generation failed: {result.stderr}")
            
            # Set proper permissions
            os.chmod(key_path, 0o600)
            os.chmod(cert_path, 0o644)
        
        logger.info("SSL certificates generated successfully")
    
    def _check_certificate_validity(self, cert_path):
        """Check if certificate exists and is valid (not expired within 30 days)."""
        if not os.path.exists(cert_path):
            return False
            
        try:
            if sys.platform == "win32":
                # Windows: Use PowerShell to check certificate expiration
                ps_script = f'''
                param($CertPath)
                try {{
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
                    $expiryDate = $cert.NotAfter
                    $warningDate = (Get-Date).AddDays(30)
                    
                    if ($expiryDate -gt $warningDate) {{
                        Write-Output "VALID"
                    }} else {{
                        Write-Output "EXPIRES_SOON"
                    }}
                }} catch {{
                    Write-Output "INVALID"
                }}
                '''
                
                result = subprocess.run([
                    "powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", ps_script, "-CertPath", cert_path
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    output = result.stdout.strip()
                    if output == "VALID":
                        logger.debug(f"Certificate {cert_path} is valid")
                        return True
                    else:
                        logger.info(f"Certificate {cert_path} needs renewal: {output}")
                        return False
                else:
                    logger.warning(f"Certificate validation failed: {result.stderr}")
                    return False
            
            else:
                # macOS/Linux: Use OpenSSL to check certificate expiration
                result = subprocess.run([
                    'openssl', 'x509', '-in', cert_path, '-noout', '-checkend', '2592000'  # 30 days in seconds
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    logger.debug(f"Certificate {cert_path} is valid")
                    return True
                else:
                    logger.info(f"Certificate {cert_path} expires within 30 days, will regenerate")
                    return False
                    
        except Exception as e:
            logger.warning(f"Certificate validation error: {e}")
            return False
    
    def _install_certificate_trust(self, cert_path):
        """Install certificate to system trust store."""
        logger.info("Installing certificate to system trust store")
        
        try:
            if sys.platform == "win32":
                # Windows: Add to Trusted Root Certification Authorities
                # Use parameterized PowerShell to prevent injection
                ps_script = '''
                param($CertPath)
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                
                # Check if certificate already exists
                $existingCerts = $store.Certificates | Where-Object { $_.Subject -like "*identity.getpostman.com*" }
                if (-not $existingCerts) {
                    $store.Add($cert)
                    Write-Output "Certificate installed to trusted root store"
                } else {
                    Write-Output "Certificate already trusted"
                }
                $store.Close()
                '''
                
                result = subprocess.run([
                    "powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", ps_script, "-CertPath", cert_path
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    logger.info("Certificate trust installation completed")
                else:
                    logger.warning(f"Certificate trust warning: {result.stderr}")
            
            else:
                # macOS: Add to System Keychain with SSL-only trust
                # Check if certificate already exists
                check_result = subprocess.run([
                    'security', 'find-certificate', '-c', 'identity.getpostman.com',
                    '/Library/Keychains/System.keychain'
                ], capture_output=True, text=True)
                
                if "identity.getpostman.com" not in check_result.stdout:
                    # Install certificate with SSL-only trust
                    result = subprocess.run([
                        'security', 'add-trusted-cert', '-d', '-r', 'trustRoot',
                        '-p', 'ssl', '-k', '/Library/Keychains/System.keychain',
                        cert_path
                    ], capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        logger.info("Certificate installed to system keychain")
                    else:
                        logger.warning(f"Certificate installation warning: {result.stderr}")
                else:
                    logger.info("Certificate already trusted")
        
        except Exception as e:
            logger.error(f"Failed to install certificate trust: {e}")
            raise
    
    def _setup_ssl_context(self):
        """Create SSL context for HTTPS server with certificate generation and trust management."""
        logger.info("Setting up SSL context")
        
        cert_path = self.config.get('ssl_cert', 'ssl/cert.pem')
        key_path = self.config.get('ssl_key', 'ssl/key.pem')
        
        # 1. Clean up any old/duplicate certificates first
        self._cleanup_old_certificates()
        
        # 2. Generate certificates if they don't exist or are expired/invalid
        needs_regeneration = (
            not os.path.exists(cert_path) or 
            not os.path.exists(key_path) or
            not self._check_certificate_validity(cert_path)
        )
        
        if needs_regeneration:
            if os.path.exists(cert_path) or os.path.exists(key_path):
                logger.info("Certificate expired or invalid, regenerating...")
            self._generate_ssl_certificate(cert_path, key_path)
        
        # 3. Install certificate to system trust store
        self._install_certificate_trust(cert_path)
        
        # 4. Create SSL context
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(cert_path, key_path)
        
        logger.info("SSL context setup completed")
        return ssl_context
    
    def _get_hosts_file_path(self):
        """Get the hosts file path for the current platform."""
        if sys.platform == "win32":
            return r"C:\Windows\System32\drivers\etc\hosts"
        else:
            return "/etc/hosts"
    
    def _cleanup_stale_hosts_entries(self):
        """Remove any existing hosts entries from previous daemon instances."""
        hosts_file = self._get_hosts_file_path()
        hosts_entry_pattern = "127.0.0.1 identity.getpostman.com"
        
        try:
            if not os.path.exists(hosts_file):
                logger.warning(f"Hosts file not found: {hosts_file}")
                return
            
            with open(hosts_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if our entry exists
            if hosts_entry_pattern in content:
                logger.info("Found stale hosts entry from previous daemon, cleaning up...")
                
                # Backup hosts file
                backup_file = hosts_file + '.backup'
                with open(backup_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # Remove our entries
                lines = content.splitlines()
                cleaned_lines = [line for line in lines if not (
                    "127.0.0.1" in line and "identity.getpostman.com" in line
                )]
                
                # Write cleaned content
                with open(hosts_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(cleaned_lines) + '\n')
                
                logger.info("Cleaned up stale hosts entries")
            
        except Exception as e:
            logger.error(f"Failed to cleanup stale hosts entries: {e}")
            # Don't fail startup for this
    
    def _setup_hosts_file(self):
        """Add hosts file entry for identity.getpostman.com."""
        hosts_file = self._get_hosts_file_path()
        hosts_entry = "127.0.0.1 identity.getpostman.com"
        
        try:
            # Read current hosts file
            with open(hosts_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if entry already exists
            if hosts_entry not in content:
                # Backup hosts file
                backup_file = hosts_file + '.backup'
                with open(backup_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # Add entry
                with open(hosts_file, 'a', encoding='utf-8') as f:
                    f.write(f"\n{hosts_entry}\n")
                
                logger.info("Added hosts file entry")
            else:
                logger.info("Hosts file entry already exists")
        
        except Exception as e:
            logger.error(f"Failed to setup hosts file: {e}")
            raise
    
    def _cleanup_hosts_file(self):
        """Remove hosts file entry for identity.getpostman.com."""
        hosts_file = self._get_hosts_file_path()
        
        try:
            if not os.path.exists(hosts_file):
                return
            
            with open(hosts_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Remove entries for identity.getpostman.com
            lines = content.splitlines()
            cleaned_lines = [line for line in lines if not (
                "127.0.0.1" in line and "identity.getpostman.com" in line
            )]
            
            # Write back if content changed
            if len(lines) != len(cleaned_lines):
                # Backup hosts file
                backup_file = hosts_file + '.backup'
                with open(backup_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # Write cleaned content
                with open(hosts_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(cleaned_lines) + '\n')
                
                logger.info("Cleaned up hosts file entries")
        
        except Exception as e:
            logger.error(f"Failed to cleanup hosts file: {e}")
    def _test_server_health(self):
        """Test server health before modifying hosts file."""
        logger.info("Testing daemon health...")
        
        try:
            # Create a test request to our own server
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Test with the actual port we're listening on using our health endpoint
            port = self.config.get('listen_port', HTTPS_PORT)
            url = f'https://127.0.0.1:{port}/health'
            
            req = urllib.request.Request(url)
            req.add_header('Host', 'identity.getpostman.com')
            
            # Try to connect with short timeout
            with urllib.request.urlopen(req, context=context, timeout=5) as response:
                logger.info("Daemon health check passed")
                return True
        
        except Exception as e:
            logger.error(f"Daemon health check failed: {e}")
            raise RuntimeError("Daemon failed health check")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.cleanup()
        sys.exit(0)
    
    def _register_cleanup_handlers(self):
        """Register cleanup handlers for graceful shutdown."""
        # Signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # atexit handlers for additional safety
        atexit.register(self._cleanup_hosts_file)
        atexit.register(self._cleanup_certificate_trust)
        
        logger.info("Cleanup handlers registered")
    
    def _start_hosts_monitor(self):
        """Start background thread to monitor hosts file integrity."""
        def monitor_loop():
            while getattr(self, '_monitoring', True):
                try:
                    hosts_file = self._get_hosts_file_path()
                    hosts_entry = "127.0.0.1 identity.getpostman.com"
                    
                    if os.path.exists(hosts_file):
                        with open(hosts_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        # Check if our entry is missing
                        if hosts_entry not in content:
                            logger.warning("Hosts file entry missing, restoring...")
                            try:
                                with open(hosts_file, 'a', encoding='utf-8') as f:
                                    f.write(f"\n{hosts_entry}\n")
                                logger.info("Restored hosts file entry")
                            except Exception as e:
                                logger.error(f"Failed to restore hosts entry: {e}")
                    
                    # Check every 30 seconds
                    time.sleep(30)
                
                except Exception as e:
                    logger.error(f"Hosts monitor error: {e}")
                    time.sleep(60)  # Longer sleep on error
        
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Started hosts file monitoring")
    
    def start(self):
        """Start the daemon and begin listening for connections."""
        # 1. Create HTTPS server
        server_address = ('127.0.0.1', self.config.get('listen_port', HTTPS_PORT))
        self.server = SSLHTTPServer(server_address, PostmanAuthHandler, self.ssl_context)
        
        logger.info(f"Daemon started on port {self.config.get('listen_port', HTTPS_PORT)}")
        
        # 2. Start server in background thread for health testing
        server_thread = threading.Thread(target=self.server.serve_forever, daemon=False)
        server_thread.start()
        
        # Give server time to initialize
        time.sleep(1)
        
        try:
            # 3. Test server health
            self._test_server_health()
            
            # 4. Only if healthy -> setup hosts file
            self._setup_hosts_file()
            
            # 5. Register cleanup handlers
            self._register_cleanup_handlers()
            
            # 6. Start hosts file monitoring
            self._start_hosts_monitor()
            
            logger.info("Daemon startup complete - all systems healthy")
            
            # 7. Wait for server thread (keep main thread alive)
            server_thread.join()
            
        except Exception as e:
            logger.error(f"Daemon startup failed: {e}")
            # Clean up on startup failure
            self.cleanup()
            raise
        except KeyboardInterrupt:
            logger.info("Daemon stopped by user")
            self.cleanup()
        finally:
            # Additional cleanup safety
            if hasattr(self, '_monitoring'):
                self._monitoring = False
    
    def _cleanup_certificate_trust(self):
        """Remove certificate from system trust store on shutdown."""
        self._remove_certificate_from_system_store("certificate trust cleanup")
    
    def cleanup(self):
        """Clean up resources on shutdown."""
        logger.info("Starting daemon cleanup...")
        
        # Stop monitoring thread
        if hasattr(self, '_monitoring'):
            self._monitoring = False
        
        # Stop server
        if self.server:
            self.server.shutdown()
            logger.info("Server stopped")
        
        # Clean up hosts file
        self._cleanup_hosts_file()
        
        # Clean up certificate trust
        self._cleanup_certificate_trust()
        
        logger.info("Daemon shutdown complete")


def find_running_daemons():
    """Find any currently running instances of this daemon."""
    running_pids = []
    current_pid = os.getpid()
    
    try:
        # Method 1: Find processes with our script name in command line
        if sys.platform == "win32":
            # Windows: Use single wmic call to get PID and CommandLine (O(1) instead of O(n))
            result = subprocess.run([
                'wmic', 'process', 'where', 'name="python.exe"', 
                'get', 'ProcessId,CommandLine', '/format:csv'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                import csv
                import io
                reader = csv.reader(io.StringIO(result.stdout))
                next(reader)  # Skip header
                for row in reader:
                    if len(row) >= 3:  # Node, CommandLine, ProcessId
                        try:
                            # CSV format: Node,CommandLine,ProcessId
                            command_line = row[1].strip()
                            pid = int(row[2].strip())
                            
                            if pid != current_pid and 'saml_enforcer.py' in command_line:
                                running_pids.append(pid)
                        except (ValueError, IndexError):
                            continue
        else:
            # Unix-like: Use ps command
            result = subprocess.run([
                'ps', 'auxww'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'saml_enforcer.py' in line and 'python' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                pid = int(parts[1])
                                if pid != current_pid:
                                    running_pids.append(pid)
                            except ValueError:
                                continue
        
        # Method 2: Check for processes listening on our target port
        target_port = 443  # Default HTTPS port
        try:
            # Load config to get actual port if different
            config_path = "config/config.json"
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    target_port = config.get('listen_port', 443)
        except:
            pass  # Use default port if config loading fails
        
        if sys.platform == "win32":
            # Windows: Get PIDs listening on port, then batch check command lines
            netstat_result = subprocess.run([
                'netstat', '-ano'
            ], capture_output=True, text=True, timeout=10)
            
            if netstat_result.returncode == 0:
                port_pids = []
                for line in netstat_result.stdout.splitlines():
                    if f':{target_port}' in line and 'LISTENING' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            try:
                                pid = int(parts[-1])
                                if pid != current_pid and pid not in running_pids:
                                    port_pids.append(pid)
                            except ValueError:
                                continue
                
                # Batch check command lines for all PIDs at once
                if port_pids:
                    pid_conditions = ' OR '.join(f'ProcessId={pid}' for pid in port_pids)
                    wmic_result = subprocess.run([
                        'wmic', 'process', 'where', f'({pid_conditions})',
                        'get', 'ProcessId,CommandLine', '/format:csv'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if wmic_result.returncode == 0:
                        import csv
                        import io
                        reader = csv.reader(io.StringIO(wmic_result.stdout))
                        next(reader, None)  # Skip header
                        for row in reader:
                            if len(row) >= 3:
                                try:
                                    command_line = row[1].strip()
                                    pid = int(row[2].strip())
                                    if 'saml_enforcer.py' in command_line:
                                        running_pids.append(pid)
                                except (ValueError, IndexError):
                                    continue
        else:
            # Unix-like: Use lsof or netstat
            try:
                lsof_result = subprocess.run([
                    'lsof', '-i', f':{target_port}', '-t'
                ], capture_output=True, text=True, timeout=10)
                
                if lsof_result.returncode == 0:
                    for pid_str in lsof_result.stdout.strip().split('\n'):
                        if pid_str:
                            try:
                                pid = int(pid_str)
                                if pid != current_pid and pid not in running_pids:
                                    # Verify this is our process
                                    ps_result = subprocess.run([
                                        'ps', '-p', str(pid), '-o', 'command', '--no-headers'
                                    ], capture_output=True, text=True, timeout=5)
                                    
                                    if ps_result.returncode == 0 and 'saml_enforcer.py' in ps_result.stdout:
                                        running_pids.append(pid)
                            except (ValueError, subprocess.TimeoutExpired):
                                continue
            except FileNotFoundError:
                # lsof not available, try netstat
                try:
                    netstat_result = subprocess.run([
                        'netstat', '-tlnp'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if netstat_result.returncode == 0:
                        for line in netstat_result.stdout.splitlines():
                            if f':{target_port}' in line and 'LISTEN' in line:
                                parts = line.split()
                                if len(parts) >= 7 and '/' in parts[-1]:
                                    try:
                                        pid_prog = parts[-1]
                                        pid = int(pid_prog.split('/')[0])
                                        if pid != current_pid and pid not in running_pids:
                                            # Verify this is our process
                                            ps_result = subprocess.run([
                                                'ps', '-p', str(pid), '-o', 'command', '--no-headers'
                                            ], capture_output=True, text=True, timeout=5)
                                            
                                            if ps_result.returncode == 0 and 'saml_enforcer.py' in ps_result.stdout:
                                                running_pids.append(pid)
                                    except (ValueError, subprocess.TimeoutExpired):
                                        continue
                except FileNotFoundError:
                    pass  # No netstat available either
        
        # Remove duplicates and return
        return list(set(running_pids))
        
    except Exception as e:
        logger.warning(f"Error finding running daemons: {e}")
        return []


def terminate_existing_daemons(pids):
    """Gracefully terminate existing daemon processes."""
    if not pids:
        return
    
    logger.info(f"Found {len(pids)} existing daemon process(es): {pids}")
    
    for pid in pids:
        try:
            logger.info(f"Attempting to gracefully terminate daemon PID {pid}")
            
            # Check if process still exists
            try:
                if sys.platform == "win32":
                    subprocess.run(['tasklist', '/FI', f'PID eq {pid}'], 
                                 capture_output=True, text=True, timeout=5)
                else:
                    subprocess.run(['kill', '-0', str(pid)], 
                                 capture_output=True, timeout=5)
            except subprocess.CalledProcessError:
                logger.info(f"Process {pid} already terminated")
                continue
            
            # Send SIGTERM (graceful shutdown signal)
            try:
                if sys.platform == "win32":
                    # Windows: Use taskkill with graceful termination
                    result = subprocess.run([
                        'taskkill', '/PID', str(pid), '/T'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode != 0:
                        logger.warning(f"Failed to send termination signal to PID {pid}: {result.stderr}")
                        continue
                else:
                    # Unix-like: Send SIGTERM
                    result = subprocess.run([
                        'kill', '-TERM', str(pid)
                    ], capture_output=True, text=True, timeout=5)
                    
                    if result.returncode != 0:
                        logger.warning(f"Failed to send SIGTERM to PID {pid}")
                        continue
                
                logger.info(f"Sent graceful termination signal to PID {pid}")
                
            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout sending termination signal to PID {pid}")
                continue
            
            # Wait for graceful shutdown (up to 10 seconds)
            logger.info(f"Waiting for PID {pid} to terminate gracefully...")
            for i in range(10):
                time.sleep(1)
                try:
                    if sys.platform == "win32":
                        check_result = subprocess.run([
                            'tasklist', '/FI', f'PID eq {pid}'
                        ], capture_output=True, text=True, timeout=5)
                        
                        if f'PID eq {pid}' not in check_result.stdout or 'No tasks are running' in check_result.stdout:
                            logger.info(f"PID {pid} terminated gracefully")
                            break
                    else:
                        subprocess.run(['kill', '-0', str(pid)], 
                                     capture_output=True, timeout=5)
                        # If we get here, process still exists
                except subprocess.CalledProcessError:
                    # Process no longer exists (kill -0 failed)
                    logger.info(f"PID {pid} terminated gracefully")
                    break
                except subprocess.TimeoutExpired:
                    continue
            else:
                # Process still running after 10 seconds, force kill
                logger.warning(f"PID {pid} did not terminate gracefully, forcing termination")
                try:
                    if sys.platform == "win32":
                        subprocess.run([
                            'taskkill', '/PID', str(pid), '/T', '/F'
                        ], capture_output=True, text=True, timeout=10)
                    else:
                        subprocess.run([
                            'kill', '-KILL', str(pid)
                        ], capture_output=True, text=True, timeout=5)
                    
                    logger.info(f"Force terminated PID {pid}")
                    
                except Exception as e:
                    logger.error(f"Failed to force terminate PID {pid}: {e}")
        
        except Exception as e:
            logger.error(f"Error terminating daemon PID {pid}: {e}")
    
    # Give a moment for cleanup to complete
    time.sleep(2)
    logger.info("Existing daemon termination completed")


def main():
    """Main entry point for the daemon."""
    
    # Check for root/admin privileges (platform-specific)
    if sys.platform == "win32":
        # Windows: Check if running as administrator
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("\n" + "="*60)
            print("⚠️  ADMINISTRATOR PRIVILEGES REQUIRED")
            print("="*60)
            print("\nThis daemon requires administrator access to:")
            print(f"  • Bind to port {HTTPS_PORT} (HTTPS)")
            print("\nPlease run PowerShell as Administrator")
            print("="*60 + "\n")
            sys.exit(1)
    else:
        # Unix-like: Check if running as root
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
    
    # Check for and terminate any existing daemon instances before starting
    print("Checking for existing daemon instances...")
    try:
        existing_pids = find_running_daemons()
        if existing_pids:
            print(f"Found {len(existing_pids)} existing daemon process(es). Terminating gracefully...")
            terminate_existing_daemons(existing_pids)
            print("Existing daemon instances terminated.")
        else:
            print("No existing daemon instances found.")
    except Exception as e:
        print(f"Warning: Error checking for existing daemons: {e}")
        print("Continuing with startup...")
    
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
