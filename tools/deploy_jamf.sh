#!/bin/bash
#############################################################################
# Postman SAML Authentication Router - JAMF Deployment Script
# 
# This script deploys the Postman authentication daemon via JAMF Pro
# Deploy as Script in JAMF Pro > Settings > Computer Management > Scripts
#
# Version: 1.0
# Date: 2025-08-17
#############################################################################

# Script parameters (configured in JAMF Pro policy)
POSTMAN_TEAM_NAME="${4:-YOUR_TEAM_NAME}"     # Parameter 4 in JAMF
OKTA_TENANT_ID="${5:-YOUR_TENANT_ID}"        # Parameter 5 in JAMF
IDP_URL="${6:-YOUR_IDP_URL}"                 # Parameter 6 in JAMF
OKTA_APP_ID="${7:-YOUR_APP_ID}"              # Parameter 7 in JAMF

# Configuration
INSTALL_DIR="/usr/local/bin/postman"
LOG_DIR="/var/log/postman"
LOG_FILE="$LOG_DIR/jamf_deployment.log"
PLIST_PATH="/Library/LaunchDaemons/com.postman.authrouter.plist"
SERVICE_NAME="com.postman.authrouter"
VERSION="1.0.0"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (via JAMF)"
    exit 1
fi

# Validate input parameters
validate_input_parameters() {
    log_message "Validating input parameters..."
    
    local validation_passed=true
    
    # Validate POSTMAN_TEAM_NAME (parameter 4)
    if [[ ! "$POSTMAN_TEAM_NAME" =~ ^[a-zA-Z0-9_-]{2,50}$ ]] || [[ "$POSTMAN_TEAM_NAME" == "YOUR_TEAM_NAME" ]]; then
        log_message "Invalid POSTMAN_TEAM_NAME: '$POSTMAN_TEAM_NAME'. Must be 2-50 alphanumeric characters, hyphens, or underscores." "ERROR"
        validation_passed=false
    fi
    
    # Validate OKTA_TENANT_ID (parameter 5)
    if [[ ! "$OKTA_TENANT_ID" =~ ^[a-zA-Z0-9_-]{5,100}$ ]] || [[ "$OKTA_TENANT_ID" == "YOUR_TENANT_ID" ]]; then
        log_message "Invalid OKTA_TENANT_ID: '$OKTA_TENANT_ID'. Must be 5-100 alphanumeric characters, hyphens, or underscores." "ERROR"
        validation_passed=false
    fi
    
    # Validate IDP_URL (parameter 6)
    if [[ ! "$IDP_URL" =~ ^https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$ ]] || [[ "$IDP_URL" == "YOUR_IDP_URL" ]]; then
        log_message "Invalid IDP_URL: '$IDP_URL'. Must be a valid HTTPS URL." "ERROR"
        validation_passed=false
    fi
    
    # Validate OKTA_APP_ID (parameter 7)
    if [[ ! "$OKTA_APP_ID" =~ ^[a-zA-Z0-9]{10,50}$ ]] || [[ "$OKTA_APP_ID" == "YOUR_APP_ID" ]]; then
        log_message "Invalid OKTA_APP_ID: '$OKTA_APP_ID'. Must be 10-50 alphanumeric characters." "ERROR"
        validation_passed=false
    fi
    
    # Additional URL validation for port numbers
    if [[ "$validation_passed" == "true" && "$IDP_URL" != "YOUR_IDP_URL" ]]; then
        # Extract port if present
        local port=$(echo "$IDP_URL" | sed -n 's/.*:\([0-9]\+\).*/\1/p')
        if [[ -n "$port" && ! "$port" =~ ^(80|443|8080|8443)$ ]]; then
            log_message "Warning: IDP_URL uses non-standard port $port. Ensure firewall allows this port." "WARN"
        fi
    fi
    
    if [[ "$validation_passed" != "true" ]]; then
        log_message "Parameter validation failed. Please check JAMF policy parameter configuration." "ERROR"
        return 1
    fi
    
    log_message "Input parameter validation passed"
    return 0
}

# Initialize logging
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# Logging function
log_message() {
    local level="${2:-INFO}"
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Check prerequisites
check_prerequisites() {
    log_message "Checking prerequisites..."
    
    local prereq_met=true
    
    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        log_message "Python 3 is required but not installed" "ERROR"
        prereq_met=false
    else
        local python_version=$(python3 --version 2>&1 | awk '{print $2}')
        log_message "Python 3 found: $python_version"
    fi
    
    # Check macOS version
    local os_version=$(sw_vers -productVersion)
    local major_version=$(echo "$os_version" | cut -d. -f1)
    local minor_version=$(echo "$os_version" | cut -d. -f2)
    
    if [[ $major_version -lt 10 ]] || [[ $major_version -eq 10 && $minor_version -lt 15 ]]; then
        log_message "macOS 10.15 or higher required (found: $os_version)" "ERROR"
        prereq_met=false
    else
        log_message "macOS version compatible: $os_version"
    fi
    
    if [[ "$prereq_met" == "false" ]]; then
        log_message "Prerequisites not met" "ERROR"
        return 1
    fi
    
    return 0
}

# Install function
install_postman_auth_router() {
    log_message "Starting installation of Postman Auth Router v$VERSION"
    
    # Validate input parameters
    if ! validate_input_parameters; then
        log_message "Input validation failed" "ERROR"
        return 1
    fi
    
    # Check prerequisites
    if ! check_prerequisites; then
        log_message "Prerequisites check failed" "ERROR"
        return 1
    fi
    
    # 1. Create installation directories
    log_message "Creating installation directories..."
    mkdir -p "$INSTALL_DIR"/{src,config,ssl,tools}
    mkdir -p "$LOG_DIR"
    
    # Set proper permissions
    chown root:wheel "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    
    # 2. Copy files from JAMF package or download
    log_message "Installing package files..."
    
    # Option 1: Files deployed via JAMF package
    if [[ -d "/tmp/postman-auth-router" ]]; then
        cp -R /tmp/postman-auth-router/* "$INSTALL_DIR/"
        log_message "Files copied from JAMF package"
    
    # Option 2: Download from corporate server with retry logic
    elif [[ -n "$PACKAGE_URL" ]]; then
        log_message "Downloading package from $PACKAGE_URL"
        
        local download_success=false
        local retry_count=0
        local max_retries=3
        local retry_delays=(1 2 4)  # Exponential backoff in seconds
        
        while [[ "$download_success" == "false" && $retry_count -lt $max_retries ]]; do
            if [[ $retry_count -gt 0 ]]; then
                log_message "Package download retry attempt $retry_count of $max_retries after ${retry_delays[$((retry_count-1))]} seconds..." "WARN"
                sleep "${retry_delays[$((retry_count-1))]}"
            fi
            
            if curl -sL --max-time 300 --user-agent "PostmanAuthRouter-JAMF/1.0" "$PACKAGE_URL" -o "/tmp/postman-auth-router.tar.gz"; then
                # Verify download
                if [[ -f "/tmp/postman-auth-router.tar.gz" && $(wc -c < "/tmp/postman-auth-router.tar.gz") -gt 1000 ]]; then
                    if tar -tzf "/tmp/postman-auth-router.tar.gz" &>/dev/null; then
                        tar -xzf "/tmp/postman-auth-router.tar.gz" -C "$INSTALL_DIR" --strip-components=1
                        rm -f "/tmp/postman-auth-router.tar.gz"
                        download_success=true
                        log_message "Package downloaded and extracted successfully"
                    else
                        log_message "Downloaded archive appears corrupt" "WARN"
                        rm -f "/tmp/postman-auth-router.tar.gz"
                    fi
                else
                    log_message "Downloaded file appears incomplete" "WARN"
                    rm -f "/tmp/postman-auth-router.tar.gz"
                fi
            else
                log_message "Package download failed (curl exit code: $?)" "WARN"
            fi
            
            if [[ "$download_success" == "false" ]]; then
                retry_count=$((retry_count + 1))
            fi
        done
        
        if [[ "$download_success" == "false" ]]; then
            log_message "Failed to download package after $max_retries attempts. Creating embedded files as fallback." "WARN"
            create_embedded_files
        fi
    
    # Option 3: Use embedded files (for minimal deployments)
    else
        log_message "Creating embedded configuration files..."
        create_embedded_files
    fi
    
    # Set file permissions
    chown -R root:wheel "$INSTALL_DIR"
    chmod -R 755 "$INSTALL_DIR"
    chmod 644 "$INSTALL_DIR"/config/*
    
    # 3. Configure hosts file
    log_message "Configuring hosts file..."
    local hosts_file="/etc/hosts"
    local start_marker="# BEGIN POSTMAN-AUTH-ROUTER-JAMF"
    local end_marker="# END POSTMAN-AUTH-ROUTER-JAMF"
    
    # Backup hosts file
    cp "$hosts_file" "$hosts_file.jamf.backup.$(date +%Y-%m-%d-%H%M%S)"
    
    # Check if entries already exist
    if ! grep -q "$start_marker" "$hosts_file"; then
        cat >> "$hosts_file" << EOF

$start_marker
127.0.0.1 identity.getpostman.com
127.0.0.1 identity.postman.co
$end_marker
EOF
        log_message "Hosts file updated successfully"
    else
        log_message "Hosts entries already configured"
    fi
    
    # 4. Setup SSL certificate (prioritize JAMF certificate payloads)
    log_message "Setting up SSL certificate..."
    
    # PREFERRED METHOD: Check for JAMF certificate payload first
    local profile_cert_found=false
    local cert_common_names=("identity.getpostman.com" "*.getpostman.com" "postman.com")
    
    for cn in "${cert_common_names[@]}"; do
        if security find-certificate -c "$cn" /Library/Keychains/System.keychain &>/dev/null; then
            log_message "Found certificate from JAMF certificate payload for: $cn"
            
            # Get certificate details with error handling
            local cert_info=""
            if command -v openssl &> /dev/null; then
                cert_info=$(security find-certificate -c "$cn" -p /Library/Keychains/System.keychain 2>/dev/null | openssl x509 -text -noout 2>/dev/null)
                if [[ $? -eq 0 && -n "$cert_info" ]]; then
                    local issuer=$(echo "$cert_info" | grep "Issuer:" | head -1)
                    local expires=$(echo "$cert_info" | grep "Not After :" | head -1)
                    if [[ -n "$issuer" ]]; then
                        log_message "Certificate details - $issuer"
                    fi
                    if [[ -n "$expires" ]]; then
                        log_message "Certificate expires - $expires"
                    fi
                else
                    log_message "Certificate found but details could not be parsed" "WARN"
                fi
            else
                log_message "OpenSSL not available for certificate detail extraction" "WARN"
            fi
            
            log_message "Using enterprise certificate from JAMF certificate payload (RECOMMENDED)"
            profile_cert_found=true
            break
        fi
    done
    
    if [[ "$profile_cert_found" == "false" ]]; then
        # FALLBACK METHOD: Check for manual certificate deployment
        local enterprise_cert="/tmp/postman-enterprise.pem"
        if [[ -f "$enterprise_cert" ]]; then
            log_message "No JAMF certificate payload found, using manual enterprise certificate"
            
            # Copy certificate with error handling
            if cp "$enterprise_cert" "$INSTALL_DIR/ssl/cert.pem" 2>/dev/null; then
                log_message "Enterprise certificate copied to installation directory"
            else
                log_message "Failed to copy enterprise certificate to installation directory" "ERROR"
                return 1
            fi
            
            # Trust certificate with error handling
            if security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$enterprise_cert" 2>/dev/null; then
                log_message "Manual enterprise certificate installed and trusted"
            else
                log_message "Failed to trust enterprise certificate - manual intervention may be required" "WARN"
                # Continue deployment as certificate might still work for HTTPS
            fi
        else
            # LAST RESORT: Generate self-signed certificate
            log_message "No JAMF certificate payload or manual certificate found" "WARN"
            log_message "RECOMMENDATION: Deploy certificates via JAMF certificate payloads for better security and management" "WARN"
            log_message "Falling back to self-signed certificate generation..." "WARN"
        
        # Use OpenSSL if available
        if command -v openssl &> /dev/null; then
            cat > "$INSTALL_DIR/ssl/cert.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = identity.getpostman.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = identity.getpostman.com
DNS.2 = identity.postman.com
DNS.3 = identity.postman.co
DNS.4 = localhost
EOF
            
            # Generate certificate with error handling
            if openssl req -new -x509 -days 365 -nodes \
                -out "$INSTALL_DIR/ssl/cert.pem" \
                -keyout "$INSTALL_DIR/ssl/key.pem" \
                -config "$INSTALL_DIR/ssl/cert.conf" \
                -extensions v3_req 2>/dev/null; then
                
                log_message "Self-signed certificate generated successfully"
                
                # Trust the certificate with error handling
                if security add-trusted-cert -d -r trustRoot \
                    -k /Library/Keychains/System.keychain \
                    "$INSTALL_DIR/ssl/cert.pem" 2>/dev/null; then
                    log_message "Self-signed certificate trusted successfully"
                else
                    log_message "Failed to trust self-signed certificate - daemon may have SSL issues" "WARN"
                    # Continue as certificate file still exists for daemon use
                fi
            else
                log_message "Failed to generate self-signed certificate with OpenSSL" "ERROR"
                log_message "CRITICAL: No SSL certificate available - deployment may fail" "ERROR"
                return 1
            fi
            else
                log_message "WARNING: OpenSSL not found, certificate generation skipped" "WARN"
            fi
        fi
    fi
    
    # 5. Create configuration file
    log_message "Creating configuration file..."
    cat > "$INSTALL_DIR/config/config.json" << EOF
{
  "postman_team_name": "$POSTMAN_TEAM_NAME",
  "okta_tenant_id": "$OKTA_TENANT_ID",
  "idp_config": {
    "idp_type": "okta",
    "idp_url": "$IDP_URL",
    "okta_app_id": "$OKTA_APP_ID"
  },
  "advanced": {
    "log_file": "$LOG_DIR/postman-auth.log",
    "daemon_port": 443,
    "health_port": 8443,
    "dns_server": "8.8.8.8",
    "timeout_seconds": 30,
    "oauth_timeout_seconds": 30
  }
}
EOF
    
    log_message "Configuration file created"
    
    # 6. Create LaunchDaemon plist
    log_message "Creating LaunchDaemon configuration..."
    cat > "$PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$SERVICE_NAME</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>$INSTALL_DIR/src/auth_router_final.py</string>
        <string>--mode</string>
        <string>enforce</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/daemon_stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/daemon_stderr.log</string>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
    <key>ProcessType</key>
    <string>Background</string>
    <key>LowPriorityIO</key>
    <false/>
    <key>Nice</key>
    <integer>0</integer>
</dict>
</plist>
EOF
    
    # Set proper permissions on plist
    chown root:wheel "$PLIST_PATH"
    chmod 644 "$PLIST_PATH"
    
    log_message "LaunchDaemon plist created"
    
    # 7. Load and start the service
    log_message "Loading and starting LaunchDaemon..."
    launchctl load "$PLIST_PATH"
    
    # Wait a moment for service to start
    sleep 3
    
    # Check if service is running
    if launchctl list | grep -q "$SERVICE_NAME"; then
        log_message "LaunchDaemon loaded and running successfully"
    else
        log_message "WARNING: LaunchDaemon may not have started properly" "WARN"
    fi
    
    # 8. Create JAMF receipt for inventory
    log_message "Creating JAMF receipt..."
    local receipt_dir="/private/var/db/receipts"
    mkdir -p "$receipt_dir"
    
    cat > "$receipt_dir/com.postman.authrouter.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PackageVersion</key>
    <string>$VERSION</string>
    <key>InstallDate</key>
    <date>$(date -u +"%Y-%m-%dT%H:%M:%SZ")</date>
    <key>InstallProcessName</key>
    <string>jamf</string>
    <key>packageid</key>
    <string>com.postman.authrouter</string>
</dict>
</plist>
EOF
    
    # 9. Create uninstall script for easy removal
    log_message "Creating uninstall script..."
    cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
# Postman Auth Router Uninstall Script

echo "Uninstalling Postman Auth Router..."

# Stop and unload service
launchctl unload /Library/LaunchDaemons/com.postman.authrouter.plist 2>/dev/null

# Remove plist
rm -f /Library/LaunchDaemons/com.postman.authrouter.plist

# Remove hosts entries
sed -i.bak '/# BEGIN POSTMAN-AUTH-ROUTER-JAMF/,/# END POSTMAN-AUTH-ROUTER-JAMF/d' /etc/hosts

# Remove certificates
security find-certificate -c "identity.getpostman.com" -a -Z | \
    awk '/SHA-1/{print $NF}' | \
    xargs -I {} security delete-certificate -Z {} /Library/Keychains/System.keychain 2>/dev/null

# Remove installation directory
rm -rf /usr/local/bin/postman

# Remove logs (optional)
# rm -rf /var/log/postman

# Remove receipt
rm -f /private/var/db/receipts/com.postman.authrouter.*

echo "Uninstall completed"
EOF
    
    chmod +x "$INSTALL_DIR/uninstall.sh"
    
    # 10. Verify installation
    log_message "Verifying installation..."
    sleep 5
    
    local verification_passed=true
    
    # Check service status
    if launchctl list | grep -q "$SERVICE_NAME"; then
        log_message "✓ LaunchDaemon is running"
    else
        log_message "✗ LaunchDaemon is not running" "ERROR"
        verification_passed=false
    fi
    
    # Check hosts file
    if grep -q "127.0.0.1.*identity.getpostman.com" /etc/hosts; then
        log_message "✓ Hosts file configured"
    else
        log_message "✗ Hosts file not configured" "ERROR"
        verification_passed=false
    fi
    
    # Check certificate
    if security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain &>/dev/null; then
        log_message "✓ Certificate installed"
    else
        log_message "⚠ Certificate not found in keychain" "WARN"
    fi
    
    # Test health endpoint with retry logic
    local health_check_passed=false
    local retry_count=0
    local max_retries=3
    local retry_delays=(5 10 15)  # Allow more time for daemon startup
    
    while [[ "$health_check_passed" == "false" && $retry_count -lt $max_retries ]]; do
        if [[ $retry_count -gt 0 ]]; then
            log_message "Health check retry attempt $retry_count of $max_retries after ${retry_delays[$((retry_count-1))]} seconds..." "WARN"
        fi
        sleep "${retry_delays[$retry_count]}"
        
        if curl -sk --max-time 15 --user-agent "PostmanAuthRouter-JAMF-HealthCheck/1.0" "https://identity.getpostman.com/health" &>/dev/null; then
            log_message "✓ Health endpoint responding"
            health_check_passed=true
        else
            retry_count=$((retry_count + 1))
            if [[ $retry_count -ge $max_retries ]]; then
                log_message "⚠ Health endpoint not accessible after $max_retries attempts (daemon may need more time)" "WARN"
            fi
        fi
    done
    
    if [[ "$verification_passed" == "true" ]]; then
        log_message "Installation completed successfully"
        return 0
    else
        log_message "Installation completed with errors" "ERROR"
        return 1
    fi
}

# Create embedded files for minimal deployment
create_embedded_files() {
    log_message "Creating minimal deployment files..."
    
    # Create Python daemon file (simplified version)
    cat > "$INSTALL_DIR/src/auth_router_final.py" << 'EOF'
#!/usr/bin/env python3
"""
Postman SAML Authentication Router - JAMF Minimal Version
Enforces SAML authentication for Postman Web and Desktop
"""

import http.server
import socketserver
import ssl
import json
import os
import sys
import argparse
from urllib.parse import urlparse, parse_qs

class PostmanAuthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Load configuration
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')
        with open(config_path) as f:
            config = json.load(f)
        
        # Parse request
        parsed_url = urlparse(self.path)
        
        # Check if this is a login request that should be redirected to SAML
        if parsed_url.path in ['/login', '/client/login']:
            # Redirect to SAML IdP
            idp_url = config['idp_config']['idp_url']
            self.send_response(302)
            self.send_header('Location', idp_url)
            self.end_headers()
            return
        
        # Health check endpoint
        if parsed_url.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy"}')
            return
        
        # Default response
        self.send_response(404)
        self.end_headers()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', default='enforce')
    args = parser.parse_args()
    
    port = 443
    
    # Create server
    with socketserver.TCPServer(("", port), PostmanAuthHandler) as httpd:
        # Configure SSL
        cert_path = os.path.join(os.path.dirname(__file__), '..', 'ssl', 'cert.pem')
        key_path = os.path.join(os.path.dirname(__file__), '..', 'ssl', 'key.pem')
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            httpd.socket = ssl.wrap_socket(httpd.socket,
                                         certfile=cert_path,
                                         keyfile=key_path,
                                         server_side=True)
        
        print(f"Postman Auth Router listening on port {port}")
        httpd.serve_forever()

if __name__ == "__main__":
    main()
EOF
    
    chmod +x "$INSTALL_DIR/src/auth_router_final.py"
    log_message "Embedded Python daemon created"
}

# Uninstall function
uninstall_postman_auth_router() {
    log_message "Starting uninstallation of Postman Auth Router"
    
    # Stop and unload service
    launchctl unload "$PLIST_PATH" 2>/dev/null
    log_message "LaunchDaemon unloaded"
    
    # Remove plist
    rm -f "$PLIST_PATH"
    log_message "LaunchDaemon plist removed"
    
    # Remove hosts entries
    local hosts_file="/etc/hosts"
    local start_marker="# BEGIN POSTMAN-AUTH-ROUTER-JAMF"
    local end_marker="# END POSTMAN-AUTH-ROUTER-JAMF"
    
    if grep -q "$start_marker" "$hosts_file"; then
        sed -i.jamf_uninstall "/^$start_marker$/,/^$end_marker$/d" "$hosts_file"
        log_message "Hosts entries removed"
    fi
    
    # Remove certificates
    security find-certificate -c "identity.getpostman.com" -a -Z | \
        awk '/SHA-1/{print $NF}' | \
        xargs -I {} security delete-certificate -Z {} /Library/Keychains/System.keychain 2>/dev/null
    log_message "Certificates removed"
    
    # Remove installation directory
    rm -rf "$INSTALL_DIR"
    log_message "Installation directory removed"
    
    # Remove receipt
    rm -f /private/var/db/receipts/com.postman.authrouter.*
    log_message "JAMF receipt removed"
    
    log_message "Uninstallation completed successfully"
    return 0
}

# Detection method for JAMF Extension Attributes
detect_installation() {
    local installed=true
    local details=()
    
    # Check receipt
    if [[ -f "/private/var/db/receipts/com.postman.authrouter.plist" ]]; then
        local receipt_version=$(defaults read /private/var/db/receipts/com.postman.authrouter.plist PackageVersion 2>/dev/null)
        if [[ "$receipt_version" == "$VERSION" ]]; then
            details+=("Receipt version matches")
        else
            installed=false
            details+=("Receipt version mismatch")
        fi
    else
        installed=false
        details+=("Receipt not found")
    fi
    
    # Check LaunchDaemon
    if launchctl list | grep -q "$SERVICE_NAME"; then
        details+=("Service running")
    else
        installed=false
        details+=("Service not running")
    fi
    
    # Check hosts file
    if grep -q "127\.0\.0\.1.*identity\.getpostman\.com" /etc/hosts; then
        details+=("Hosts configured")
    else
        installed=false
        details+=("Hosts not configured")
    fi
    
    if [[ "$installed" == "true" ]]; then
        echo "Installed: ${details[*]}"
        return 0
    else
        echo "Not installed: ${details[*]}"
        return 1
    fi
}

# Main execution
log_message "=========================================="
log_message "Postman Auth Router JAMF Deployment Script"
log_message "Mode: ${1:-install}"
log_message "=========================================="

case "${1:-install}" in
    "install")
        if install_postman_auth_router; then
            exit 0
        else
            exit 1
        fi
        ;;
    "uninstall")
        if uninstall_postman_auth_router; then
            exit 0
        else
            exit 1
        fi
        ;;
    "detect")
        detect_installation
        exit $?
        ;;
    *)
        log_message "Invalid mode: ${1}" "ERROR"
        log_message "Valid modes: install, uninstall, detect"
        exit 1
        ;;
esac