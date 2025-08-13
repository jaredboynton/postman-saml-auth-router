#!/bin/bash

#############################################################################
# One-Click Demo Script for Postman SAML Authentication Router
# 
# Sets up and runs the daemon for local demonstration
#############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

clear
echo "======================================================================"
echo "     🚀 Postman SAML Authentication Router - Quick Demo"
echo "======================================================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This demo requires root access to:${NC}"
   echo "  - Bind to port 443"
   echo "  - Modify /etc/hosts"
   echo ""
   echo -e "${YELLOW}Please run: sudo ./demo.sh${NC}"
   exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is required but not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Running as root${NC}"
echo -e "${GREEN}✓ Python 3 found${NC}"
echo ""

# Kill any existing daemon
echo "Cleaning up any existing processes..."
pkill -f "auth_router_final.py" 2>/dev/null || true
echo -e "${GREEN}✓ Cleaned up${NC}"
echo ""

# Generate certificates if missing
if [ ! -f "ssl/cert.pem" ] || [ ! -f "ssl/key.pem" ]; then
    echo "Generating SSL certificates..."
    ./generate_certs.sh
else
    echo -e "${GREEN}✓ SSL certificates found${NC}"
fi

# Check for config
if [ ! -f "config/config.json" ]; then
    echo ""
    echo -e "${YELLOW}No configuration found!${NC}"
    echo ""
    echo "Do you want to:"
    echo "  1) Use demo configuration (mock Okta)"
    echo "  2) Enter your real Okta configuration"
    echo ""
    read -p "Choice (1 or 2): " choice
    
    if [ "$choice" = "2" ]; then
        echo ""
        read -p "Enter your Okta domain (e.g., company.okta.com): " okta_domain
        read -p "Enter your Okta app ID (e.g., 0oa2e5ac275gNOI035d7): " okta_app_id
        read -p "Enter your integration ID (e.g., exk2e5ac26g30Z4QB5d7): " integration_id
        
        cat > config/config.json << EOF
{
  "idp_url": "https://${okta_domain}/app/getpostman/${integration_id}/sso/saml",
  "okta_app_id": "${okta_app_id}"
}
EOF
        echo -e "${GREEN}✓ Configuration created${NC}"
    else
        # Use demo config
        cat > config/config.json << 'EOF'
{
  "idp_url": "https://demo.okta.com/app/postman/demo123/sso/saml",
  "okta_app_id": "demo_app_123"
}
EOF
        echo -e "${YELLOW}⚠ Using demo configuration (won't actually authenticate)${NC}"
    fi
else
    echo -e "${GREEN}✓ Configuration found${NC}"
fi

# Check hosts file
if grep -q "identity.getpostman.com" /etc/hosts; then
    echo -e "${GREEN}✓ Hosts entry exists${NC}"
else
    echo "Adding hosts entry..."
    echo "127.0.0.1 identity.getpostman.com" >> /etc/hosts
    echo -e "${GREEN}✓ Hosts entry added${NC}"
fi

# Flush DNS cache
echo "Flushing DNS cache..."
dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true
echo -e "${GREEN}✓ DNS cache flushed${NC}"

echo ""
echo "======================================================================"
echo "                    🚀 Starting the Daemon"
echo "======================================================================"
echo ""
echo -e "${BLUE}The daemon will run in the foreground for this demo.${NC}"
echo -e "${BLUE}Press Ctrl+C to stop when done.${NC}"
echo ""
echo "======================================================================"
echo "                    📝 How to Test"
echo "======================================================================"
echo ""
echo "1. Open a browser (Chrome/Safari/Firefox)"
echo ""
echo "2. Navigate to any of these URLs:"
echo -e "   ${GREEN}https://identity.getpostman.com/login${NC}"
echo -e "   ${GREEN}https://go.postman.co/${NC}"
echo ""
echo "3. You should see:"
echo "   - Certificate warning (accept it - it's our self-signed cert)"
echo "   - Redirect to your IDP for authentication"
echo "   - After auth, redirect back to Postman"
echo ""
echo "4. To see the flow in action:"
echo "   - Open Developer Tools > Network tab"
echo "   - Clear cookies to test fresh authentication"
echo ""
echo "======================================================================"
echo "                    🧹 Cleanup Command"
echo "======================================================================"
echo ""
echo "When done, run this to clean up:"
echo -e "${YELLOW}sudo ./cleanup.sh${NC}"
echo ""
echo "======================================================================"
echo ""
echo -e "${GREEN}Starting daemon...${NC}"
echo ""

# Start the daemon
python3 src/auth_router_final.py config/config.json