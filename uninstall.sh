#!/bin/bash

#############################################################################
# Postman SAML Authentication Router - Uninstall Script
#
# Completely removes the Postman authentication daemon
#############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "======================================================================"
echo "     Postman SAML Authentication Router - Uninstaller"
echo "======================================================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}"
   exit 1
fi

echo -e "${YELLOW}This will completely remove the Postman SAML Authentication Router.${NC}"
read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    exit 0
fi

echo ""
echo "Stopping daemon..."

# Stop and unload daemon
if launchctl list | grep -q "com.postman.auth.router"; then
    launchctl unload /Library/LaunchDaemons/com.postman.auth.router.plist 2>/dev/null || true
    echo -e "${GREEN}✓ Daemon stopped${NC}"
else
    echo "  Daemon not running"
fi

# Kill any remaining processes
pkill -f "auth_router_final.py" 2>/dev/null || true

echo "Removing files..."

# Remove LaunchDaemon
rm -f /Library/LaunchDaemons/com.postman.auth.router.plist
echo -e "${GREEN}✓ LaunchDaemon removed${NC}"

# Remove installation directory
rm -rf "/Library/Application Support/Postman/AuthRouter"
echo -e "${GREEN}✓ Application files removed${NC}"

# Remove logs
rm -rf /var/log/postman
echo -e "${GREEN}✓ Logs removed${NC}"

echo "Cleaning hosts file..."

# Remove hosts entry
sed -i '' '/identity.getpostman.com/d' /etc/hosts
echo -e "${GREEN}✓ Hosts file cleaned${NC}"

echo "Flushing DNS cache..."

# Flush DNS cache
dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true
echo -e "${GREEN}✓ DNS cache flushed${NC}"

echo ""
echo "======================================================================"
echo -e "${GREEN}        Uninstall Complete!${NC}"
echo "======================================================================"
echo ""
echo "The Postman SAML Authentication Router has been completely removed."
echo "You can now access Postman directly without SAML enforcement."
echo ""

exit 0