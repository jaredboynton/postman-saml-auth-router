#!/bin/bash

#############################################################################
# Cleanup Script for Postman SAML Auth Router Demo
#############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "======================================================================"
echo "     🧹 Cleaning Up Postman SAML Auth Router Demo"
echo "======================================================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script requires root access${NC}"
   echo -e "${YELLOW}Please run: sudo ./cleanup.sh${NC}"
   exit 1
fi

# Kill daemon
echo "Stopping daemon..."
pkill -f "auth_router_final.py" 2>/dev/null || true
echo -e "${GREEN}✓ Daemon stopped${NC}"

# Remove hosts entry
echo "Removing hosts entry..."
sed -i '' '/identity.getpostman.com/d' /etc/hosts
echo -e "${GREEN}✓ Hosts entry removed${NC}"

# Remove trusted certificate from system keychain
echo "Removing trusted certificate from system keychain..."
security delete-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null || true
echo -e "${GREEN}✓ Trusted certificate removed${NC}"

# Flush DNS
echo "Flushing DNS cache..."
dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true
echo -e "${GREEN}✓ DNS cache flushed${NC}"

# Optional: Remove demo config
echo ""
read -p "Remove demo configuration? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -f config/config.json
    echo -e "${GREEN}✓ Configuration removed${NC}"
fi

echo ""
echo -e "${GREEN}✅ Cleanup complete!${NC}"
echo ""
echo "The demo environment has been reset."
echo "You can run ./demo.sh again anytime."
echo ""

exit 0