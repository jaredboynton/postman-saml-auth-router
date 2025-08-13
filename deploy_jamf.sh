#!/bin/bash

#############################################################################
# Postman SAML Authentication Router - JAMF Deployment Script
# 
# This script deploys the Postman authentication daemon via JAMF
# It can be run as a policy script or via Self Service
#
# Author: Jared Boynton
# Version: 1.0
# Date: 2025-08-13
#############################################################################

set -e

# Configuration
INSTALL_DIR="/Library/Application Support/Postman/AuthRouter"
LAUNCHDAEMON_PLIST="/Library/LaunchDaemons/com.postman.auth.router.plist"
LOG_DIR="/var/log/postman"
LOG_FILE="$LOG_DIR/auth-router.log"
PYTHON_PATH="/usr/bin/python3"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    log "ERROR: $1"
    exit 1
}

# Success message
success() {
    echo -e "${GREEN}✓ $1${NC}"
    log "SUCCESS: $1"
}

# Warning message
warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
    log "WARNING: $1"
}

#############################################################################
# Pre-flight checks
#############################################################################

echo "======================================================================"
echo "         Postman SAML Authentication Router - JAMF Deployment"
echo "======================================================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error_exit "This script must be run as root (use sudo)"
fi

# Check Python availability
if ! command -v python3 &> /dev/null; then
    error_exit "Python 3 is required but not installed"
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
success "Python $PYTHON_VERSION found"

#############################################################################
# Stop existing daemon if running
#############################################################################

if launchctl list | grep -q "com.postman.auth.router"; then
    warning "Stopping existing daemon..."
    launchctl unload "$LAUNCHDAEMON_PLIST" 2>/dev/null || true
    
    # Kill any remaining processes
    pkill -f "auth_router_final.py" 2>/dev/null || true
    
    success "Existing daemon stopped"
fi

#############################################################################
# Create installation directory
#############################################################################

log "Creating installation directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/src"
mkdir -p "$INSTALL_DIR/config"
mkdir -p "$INSTALL_DIR/ssl"
mkdir -p "$LOG_DIR"

success "Installation directories created"

#############################################################################
# Copy daemon files
#############################################################################

log "Installing daemon files..."

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Copy main daemon script
if [[ -f "$SCRIPT_DIR/src/auth_router_final.py" ]]; then
    cp "$SCRIPT_DIR/src/auth_router_final.py" "$INSTALL_DIR/src/"
    chmod 755 "$INSTALL_DIR/src/auth_router_final.py"
    success "Daemon script installed"
else
    error_exit "Daemon script not found at $SCRIPT_DIR/src/auth_router_final.py"
fi

# Copy configuration
if [[ -f "$SCRIPT_DIR/config/config.json" ]]; then
    cp "$SCRIPT_DIR/config/config.json" "$INSTALL_DIR/config/"
    chmod 644 "$INSTALL_DIR/config/config.json"
    success "Configuration installed"
else
    # Create default configuration
    cat > "$INSTALL_DIR/config/config.json" << 'EOF'
{
    "okta_app_id": "0oa2e5ac275gNOI035d7",
    "idp_url": "https://postman.okta.com/app/getpostman/exk2e5ac26g30Z4QB5d7/sso/saml",
    "okta_integration_id": "exk2e5ac26g30Z4QB5d7"
}
EOF
    warning "Using default Postman Okta configuration"
fi

#############################################################################
# Generate SSL certificate
#############################################################################

log "Generating SSL certificate..."

openssl req -new -x509 -days 365 -nodes \
    -out "$INSTALL_DIR/ssl/cert.pem" \
    -keyout "$INSTALL_DIR/ssl/key.pem" \
    -subj "/C=US/ST=California/L=San Francisco/O=Postman/CN=identity.getpostman.com" \
    2>/dev/null

chmod 600 "$INSTALL_DIR/ssl/key.pem"
chmod 644 "$INSTALL_DIR/ssl/cert.pem"

success "SSL certificate generated"

#############################################################################
# Create LaunchDaemon plist
#############################################################################

log "Creating LaunchDaemon..."

cat > "$LAUNCHDAEMON_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.postman.auth.router</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_PATH</string>
        <string>$INSTALL_DIR/src/auth_router_final.py</string>
        <string>$INSTALL_DIR/config/config.json</string>
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    
    <key>StandardOutPath</key>
    <string>$LOG_FILE</string>
    
    <key>StandardErrorPath</key>
    <string>$LOG_FILE</string>
    
    <key>UserName</key>
    <string>root</string>
    
    <key>GroupName</key>
    <string>wheel</string>
    
    <key>InitGroups</key>
    <true/>
    
    <key>SessionCreate</key>
    <true/>
</dict>
</plist>
EOF

chmod 644 "$LAUNCHDAEMON_PLIST"
success "LaunchDaemon created"

#############################################################################
# Update hosts file
#############################################################################

log "Updating hosts file..."

# Remove any existing entries
sed -i '' '/identity.getpostman.com/d' /etc/hosts

# Add new entry
echo "127.0.0.1 identity.getpostman.com" >> /etc/hosts

success "Hosts file updated"

#############################################################################
# Flush DNS cache
#############################################################################

log "Flushing DNS cache..."
dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true

success "DNS cache flushed"

#############################################################################
# Load and start daemon
#############################################################################

log "Starting daemon..."

launchctl load -w "$LAUNCHDAEMON_PLIST"

# Wait for daemon to start
sleep 2

# Check if daemon is running
if launchctl list | grep -q "com.postman.auth.router"; then
    success "Daemon started successfully"
else
    error_exit "Failed to start daemon"
fi

#############################################################################
# Create uninstall script
#############################################################################

cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash

echo "Uninstalling Postman SAML Authentication Router..."

# Stop daemon
launchctl unload /Library/LaunchDaemons/com.postman.auth.router.plist 2>/dev/null || true

# Remove files
rm -f /Library/LaunchDaemons/com.postman.auth.router.plist
rm -rf "/Library/Application Support/Postman/AuthRouter"

# Clean hosts file
sed -i '' '/identity.getpostman.com/d' /etc/hosts

# Flush DNS
dscacheutil -flushcache 2>/dev/null || true

echo "✓ Uninstall complete"
EOF

chmod 755 "$INSTALL_DIR/uninstall.sh"
success "Uninstall script created"

#############################################################################
# Final verification
#############################################################################

echo ""
echo "======================================================================"
echo "                     Installation Complete!"
echo "======================================================================"
echo ""
echo "✅ Daemon installed to: $INSTALL_DIR"
echo "✅ LaunchDaemon: $LAUNCHDAEMON_PLIST"
echo "✅ Logs: $LOG_FILE"
echo "✅ Uninstall script: $INSTALL_DIR/uninstall.sh"
echo ""
echo "The Postman SAML Authentication Router is now active."
echo "All traffic to identity.getpostman.com will be routed through SAML."
echo ""
echo "To test: Open https://go.postman.co in your browser"
echo "To uninstall: Run sudo $INSTALL_DIR/uninstall.sh"
echo ""
echo "======================================================================"

# Log completion for JAMF
echo "<result>SUCCESS: Postman SAML Authentication Router deployed</result>"

exit 0