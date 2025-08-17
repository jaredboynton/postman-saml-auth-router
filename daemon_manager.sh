#!/bin/bash
# Postman Auth Daemon Manager
# Handles certificate trust and daemon lifecycle management

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run with sudo: sudo ./daemon_manager.sh${NC}"
    exit 1
fi

case "$1" in
    start)
        echo -e "${GREEN}Starting Postman Auth Daemon...${NC}"
        
        # Kill any existing daemon
        echo "Checking for existing daemon processes..."
        if pgrep -f "python.*auth_router" > /dev/null; then
            echo -e "${YELLOW}Found existing daemon, killing it...${NC}"
            pkill -9 -f "python.*auth_router" || true
            sleep 1
        fi
        
        # Check port 443
        if lsof -i :443 | grep -q LISTEN; then
            echo -e "${YELLOW}Port 443 is in use, cleaning up...${NC}"
            lsof -i :443 | grep LISTEN | awk '{print $2}' | xargs kill -9 2>/dev/null || true
            sleep 1
        fi
        
        # Start daemon
        echo -e "${GREEN}Starting daemon in ENFORCE mode...${NC}"
        python3 src/auth_router_final.py --mode enforce &
        
        sleep 2
        if pgrep -f "auth_router_final" > /dev/null; then
            echo -e "${GREEN}✓ Daemon started successfully!${NC}"
            echo "Test with: curl -k https://identity.getpostman.com/health"
        else
            echo -e "${RED}✗ Failed to start daemon${NC}"
            exit 1
        fi
        ;;
        
    stop)
        echo -e "${YELLOW}Stopping Postman Auth Daemon...${NC}"
        pkill -9 -f "python.*auth_router" || true
        echo -e "${GREEN}✓ Daemon stopped${NC}"
        ;;
        
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
        
    status)
        if pgrep -f "auth_router_final" > /dev/null; then
            echo -e "${GREEN}✓ Daemon is running${NC}"
            echo ""
            echo "Health check:"
            curl -sk https://identity.getpostman.com/health | python3 -m json.tool
        else
            echo -e "${RED}✗ Daemon is not running${NC}"
        fi
        ;;
        
    logs)
        echo -e "${GREEN}Showing daemon logs...${NC}"
        echo "Press Ctrl+C to stop viewing logs"
        echo ""
        tail -f /var/log/postman-auth.log
        ;;
        
    generate-cert)
        echo -e "${GREEN}Generating SSL certificate...${NC}"
        
        if [ -f "./generate_certs.sh" ]; then
            ./generate_certs.sh
            echo -e "${GREEN}✓ Certificate generated successfully!${NC}"
        else
            echo -e "${RED}✗ generate_certs.sh not found${NC}"
            exit 1
        fi
        ;;
        
    trust-cert)
        echo -e "${GREEN}Setting up certificate trust...${NC}"
        
        # Check if certificate exists
        if [ ! -f "ssl/cert.pem" ]; then
            echo -e "${YELLOW}Certificate not found. Generating...${NC}"
            $0 generate-cert
        fi
        
        # Remove old certificate
        echo "Removing any existing certificate..."
        security delete-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null || true
        
        # Add new certificate with trust
        echo "Adding certificate with SSL trust..."
        security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ssl/cert.pem
        
        echo -e "${GREEN}✓ Certificate trusted successfully!${NC}"
        echo ""
        echo "Verification:"
        echo -n "Certificate in keychain: "
        if security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null | grep -q "identity.getpostman.com"; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}✗${NC}"
        fi
        ;;
        
    setup)
        echo -e "${GREEN}Complete setup process...${NC}"
        
        # 1. Check hosts file
        echo "Checking hosts file..."
        for domain in "identity.getpostman.com" "identity.postman.co"; do
            if grep -q "$domain" /etc/hosts; then
                echo -e "  ${GREEN}✓${NC} $domain"
            else
                echo -e "  ${RED}✗${NC} $domain - adding..."
                echo "127.0.0.1 $domain" >> /etc/hosts
            fi
        done
        
        # 2. Check certificate
        echo ""
        echo "Checking certificate..."
        if [ -f "ssl/cert.pem" ]; then
            echo -e "  ${GREEN}✓${NC} Certificate file exists"
            # Check SAN domains
            echo "  Domains in certificate:"
            openssl x509 -in ssl/cert.pem -text -noout | grep DNS: | sed 's/^/    /'
        else
            echo -e "  ${YELLOW}✗${NC} Certificate not found - generating..."
            $0 generate-cert
        fi
        
        # 3. Trust certificate
        echo ""
        $0 trust-cert
        
        # 4. Start daemon
        echo ""
        $0 start
        ;;
        
    *)
        echo "Postman Auth Daemon Manager"
        echo ""
        echo "Usage: sudo $0 {start|stop|restart|status|generate-cert|trust-cert|setup}"
        echo ""
        echo "Commands:"
        echo "  start        - Start the daemon (kills existing first)"
        echo "  stop         - Stop the daemon"
        echo "  restart      - Restart the daemon"
        echo "  status       - Check daemon status and health"
        echo "  generate-cert- Generate SSL certificates"
        echo "  trust-cert   - Setup certificate trust (auto-generates if missing)"
        echo "  setup        - Complete setup (hosts, cert, daemon)"
        exit 1
        ;;
esac