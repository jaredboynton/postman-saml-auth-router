#!/bin/bash
# Postman Auth Daemon Manager
# Handles certificate trust and daemon lifecycle management

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LOG_FILE="/var/log/postman-auth.log"
FALLBACK_LOG_FILE="$HOME/.postman-auth.log"

# Markers for safe hosts file management
START_MARKER="# BEGIN POSTMAN-AUTH-ROUTER"
END_MARKER="# END POSTMAN-AUTH-ROUTER"

# Helper function to add hosts entries
add_hosts_entries() {
    if ! grep -q "$START_MARKER" /etc/hosts; then
        echo -e "${YELLOW}Adding hosts entries...${NC}"
        
        # Backup hosts file
        cp /etc/hosts /etc/hosts.backup.$(date +%Y%m%d_%H%M%S)
        
        # Add marked section
        cat >> /etc/hosts << EOF

$START_MARKER
# Postman SAML Enforcement - Redirects authentication to localhost
127.0.0.1 identity.getpostman.com
127.0.0.1 identity.postman.co
127.0.0.1 id.gw.postman.com
$END_MARKER
EOF
        echo -e "${GREEN}✓ Hosts entries added${NC}"
    else
        echo -e "${GREEN}✓ Hosts entries already present${NC}"
    fi
}

# Helper function to remove hosts entries
remove_hosts_entries() {
    if grep -q "$START_MARKER" /etc/hosts; then
        echo -e "${YELLOW}Removing hosts entries...${NC}"
        
        # Create backup
        cp /etc/hosts /etc/hosts.backup.$(date +%Y%m%d_%H%M%S)
        
        # Remove marked section
        sed -i.bak "/$START_MARKER/,/$END_MARKER/d" /etc/hosts
        echo -e "${GREEN}✓ Hosts entries removed${NC}"
    else
        echo -e "${YELLOW}⚠ No hosts entries to remove${NC}"
    fi
}

# Check dependencies
check_dependencies() {
    local missing=0
    
    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}✗ Python 3 is required but not installed${NC}"
        missing=1
    else
        PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        echo -e "${GREEN}✓ Python $PY_VERSION found${NC}"
    fi
    
    # Check OpenSSL
    if ! command -v openssl &> /dev/null; then
        echo -e "${RED}✗ OpenSSL is required but not installed${NC}"
        missing=1
    else
        echo -e "${GREEN}✓ OpenSSL found${NC}"
    fi
    
    # Check nslookup (for DNS checks)
    if ! command -v nslookup &> /dev/null; then
        echo -e "${YELLOW}⚠ nslookup not found (optional, for DNS verification)${NC}"
    fi
    
    return $missing
}

# Check if running as root (but not for help)
if [ "$1" != "--help" ] && [ "$1" != "-h" ] && [ "$1" != "help" ]; then
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}Please run with sudo: sudo $0 $@${NC}"
        exit 1
    fi
fi

case "$1" in
    start)
        echo -e "${GREEN}Starting Postman Auth Daemon...${NC}"
        
        # Add hosts entries before starting daemon
        add_hosts_entries
        
        # Kill any existing daemon
        echo "Checking for existing daemon processes..."
        if pgrep -f "python.*saml_enforcer" > /dev/null; then
            echo -e "${YELLOW}Found existing daemon, killing it...${NC}"
            pkill -9 -f "python.*saml_enforcer" || true
            sleep 1
        fi
        
        # Check port 443
        if lsof -i :443 | grep -q LISTEN; then
            echo -e "${YELLOW}Port 443 is in use, cleaning up...${NC}"
            lsof -i :443 | grep LISTEN | awk '{print $2}' | xargs kill -9 2>/dev/null || true
            sleep 1
        fi
        
        # Start daemon
        echo -e "${GREEN}Starting daemon...${NC}"
        python3 src/saml_enforcer.py &
        
        sleep 2
        if pgrep -f "saml_enforcer" > /dev/null; then
            echo -e "${GREEN}✓ Daemon started successfully!${NC}"
            echo "Test with: curl -k https://identity.getpostman.com/health"
        else
            echo -e "${RED}✗ Failed to start daemon${NC}"
            # Clean up hosts entries if daemon failed to start
            remove_hosts_entries
            exit 1
        fi
        ;;
        
    stop)
        echo -e "${YELLOW}Stopping Postman Auth Daemon...${NC}"
        pkill -9 -f "python.*saml_enforcer" || true
        echo -e "${GREEN}✓ Daemon stopped${NC}"
        
        # Remove hosts entries after stopping daemon
        remove_hosts_entries
        ;;
        
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
        
    status)
        if pgrep -f "saml_enforcer" > /dev/null; then
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
        
    cert|certificate|certs)
        echo -e "${GREEN}Managing SSL Certificates...${NC}"
        echo ""
        
        CERT_DIR="ssl"
        CERT_FILE="$CERT_DIR/cert.pem"
        KEY_FILE="$CERT_DIR/key.pem"
        CERT_DAYS=365
        
        # 1. Check if certificates exist
        if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
            echo -e "${GREEN}✓ Certificates found:${NC}"
            echo "  Certificate: $(pwd)/$CERT_FILE"
            echo "  Private Key: $(pwd)/$KEY_FILE"
            
            # Check certificate validity
            CERT_END_DATE=$(openssl x509 -enddate -noout -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
            if [ -n "$CERT_END_DATE" ]; then
                echo "  Valid Until: $CERT_END_DATE"
            fi
            echo ""
            
            # 2. Check if trusted
            if security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null | grep -q "identity.getpostman.com"; then
                echo -e "${GREEN}✓ Certificate is already trusted in system keychain${NC}"
                echo ""
                echo "No action needed - certificates are ready!"
            else
                echo -e "${YELLOW}⚠ Certificate exists but is NOT trusted${NC}"
                echo ""
                echo "Adding certificate to system keychain..."
                security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CERT_FILE"
                echo -e "${GREEN}✓ Certificate now trusted!${NC}"
            fi
        else
            # 3. Certificates don't exist - generate them
            echo -e "${YELLOW}No certificates found. Generating new certificates...${NC}"
            echo ""
            
            # Create SSL directory if needed
            if [ ! -d "$CERT_DIR" ]; then
                echo "Creating SSL directory..."
                mkdir -p "$CERT_DIR"
            fi
            
            # Check for cert.conf
            if [ ! -f "$CERT_DIR/cert.conf" ]; then
                echo -e "${RED}✗ Certificate configuration not found at $CERT_DIR/cert.conf${NC}"
                echo "This file is required for certificate generation"
                exit 1
            fi
            
            echo "Generating self-signed certificate (valid for $CERT_DAYS days)..."
            
            # Generate certificate
            openssl req -new -x509 -days $CERT_DAYS -nodes \
                -out "$CERT_FILE" \
                -keyout "$KEY_FILE" \
                -config "$CERT_DIR/cert.conf" \
                -extensions v3_req 2>/dev/null
            
            if [ $? -eq 0 ]; then
                # Set permissions
                chmod 600 "$KEY_FILE"
                chmod 644 "$CERT_FILE"
                echo -e "${GREEN}✓ Certificates generated successfully!${NC}"
                echo "  Certificate: $(pwd)/$CERT_FILE"
                echo "  Private Key: $(pwd)/$KEY_FILE"
                echo ""
                
                # Trust the new certificate
                echo "Adding certificate to system keychain..."
                security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CERT_FILE"
                echo -e "${GREEN}✓ Certificate trusted!${NC}"
            else
                echo -e "${RED}✗ Certificate generation failed${NC}"
                echo "Check that OpenSSL is installed and cert.conf is valid"
                exit 1
            fi
        fi
        
        # 4. Show certificate details
        echo ""
        echo "Certificate domains (SAN):"
        openssl x509 -in "$CERT_FILE" -text -noout 2>/dev/null | grep DNS: | sed 's/^/  /'
        ;;
        
    # Keep for backward compatibility
    generate-cert|trust-cert)
        # Redirect to unified cert command
        $0 cert
        ;;
        
    setup)
        echo -e "${GREEN}Postman Auth Router Setup${NC}"
        echo "=================================="
        echo ""
        
        # Check dependencies first
        echo "Checking dependencies..."
        if ! check_dependencies; then
            echo -e "${RED}✗ Missing dependencies. Please install them first.${NC}"
            exit 1
        fi
        echo ""
        
        # Explain what will happen
        echo "This will configure your system for Postman SAML authentication:"
        echo "  1. Add entries to /etc/hosts (with markers for safe removal)"
        echo "  2. Generate/trust SSL certificates"
        echo "  3. Configure from template (if needed)"
        echo "  4. Start the authentication daemon"
        echo ""
        
        # Get confirmation
        read -p "Continue with setup? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Setup cancelled."
            exit 0
        fi
        echo ""
        
        # 1. Setup hosts file using helper function
        add_hosts_entries
        
        # 2. Handle certificates
        echo ""
        $0 cert
        
        # 3. Setup config from template if needed
        echo ""
        echo "Checking configuration..."
        if [ ! -f "config/config.json" ]; then
            if [ -f "config/config.json.template" ]; then
                echo "Creating config from template..."
                cp config/config.json.template config/config.json
                echo -e "${YELLOW}⚠ Please edit config/config.json with your IDP settings${NC}"
                echo "  Required: postman_team_name, okta_tenant_id (or equivalent)"
                echo ""
                read -p "Press Enter to continue after editing config..." 
            else
                echo -e "${RED}✗ Config template not found${NC}"
                exit 1
            fi
        else
            echo -e "  ${GREEN}✓${NC} Config file exists"
        fi
        
        # 4. Start daemon
        echo ""
        $0 start
        
        # 5. Run preflight checks
        echo ""
        echo "Running preflight checks..."
        sleep 2
        $0 preflight
        echo ""
        echo "Setup complete! To remove everything: sudo $0 cleanup"
        ;;
        
    preflight)
        echo -e "${GREEN}Running preflight checks...${NC}"
        echo "Validating configuration before manual testing"
        echo ""
        
        ERRORS=0
        WARNINGS=0
        
        # 1. Check hosts file entries
        echo "Checking hosts file configuration..."
        for domain in "identity.getpostman.com" "identity.postman.co"; do
            if grep -q "127.0.0.1.*$domain" /etc/hosts; then
                echo -e "  ${GREEN}✓${NC} $domain redirected to localhost"
            else
                echo -e "  ${RED}✗${NC} $domain NOT in hosts file"
                ERRORS=$((ERRORS + 1))
            fi
        done
        
        # 2. Check certificate exists and is trusted
        echo ""
        echo "Checking certificate configuration..."
        if [ -f "ssl/cert.pem" ]; then
            echo -e "  ${GREEN}✓${NC} Certificate exists"
            
            # Check SAN domains
            SAN_DOMAINS=$(openssl x509 -in ssl/cert.pem -text -noout | grep -A1 "Subject Alternative Name" | grep DNS: | tr ',' '\n' | grep DNS: | wc -l)
            if [ "$SAN_DOMAINS" -ge 4 ]; then
                echo -e "  ${GREEN}✓${NC} Certificate has $SAN_DOMAINS SAN domains"
            else
                echo -e "  ${YELLOW}⚠${NC} Certificate only has $SAN_DOMAINS SAN domains (expected 4+)"
                WARNINGS=$((WARNINGS + 1))
            fi
            
            # Check if trusted
            if security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null | grep -q "identity.getpostman.com"; then
                echo -e "  ${GREEN}✓${NC} Certificate is in system keychain"
            else
                echo -e "  ${RED}✗${NC} Certificate not in system keychain"
                ERRORS=$((ERRORS + 1))
            fi
        else
            echo -e "  ${RED}✗${NC} Certificate not found"
            ERRORS=$((ERRORS + 1))
        fi
        
        # 3. Check daemon is running
        echo ""
        echo "Checking daemon status..."
        if pgrep -f "saml_enforcer" > /dev/null; then
            echo -e "  ${GREEN}✓${NC} Daemon is running"
            
            # Check health endpoint
            if curl -sk https://identity.getpostman.com/health 2>/dev/null | grep -q "healthy"; then
                echo -e "  ${GREEN}✓${NC} Health endpoint responding"
            else
                echo -e "  ${YELLOW}⚠${NC} Health endpoint not responding correctly"
                WARNINGS=$((WARNINGS + 1))
            fi
        else
            echo -e "  ${RED}✗${NC} Daemon is not running"
            ERRORS=$((ERRORS + 1))
        fi
        
        # 4. Check config exists
        echo ""
        echo "Checking configuration..."
        if [ -f "config/config.json" ]; then
            echo -e "  ${GREEN}✓${NC} Config file exists"
            
            # Check if it's not just the template
            if diff -q config/config.json config/config.json.template > /dev/null 2>&1; then
                echo -e "  ${YELLOW}⚠${NC} Config appears to be unmodified template"
                WARNINGS=$((WARNINGS + 1))
            else
                echo -e "  ${GREEN}✓${NC} Config has been customized"
            fi
        else
            echo -e "  ${RED}✗${NC} Config file not found"
            ERRORS=$((ERRORS + 1))
        fi
        
        # 5. Check DNS resolution
        echo ""
        echo "Checking DNS configuration..."
        if command -v nslookup &> /dev/null; then
            REAL_IP=$(nslookup identity.getpostman.com 8.8.8.8 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -n1)
            if [ -n "$REAL_IP" ]; then
                echo -e "  ${GREEN}✓${NC} External DNS resolution working (nslookup)"
            else
                echo -e "  ${YELLOW}⚠${NC} Could not verify external DNS with nslookup"
                WARNINGS=$((WARNINGS + 1))
            fi
        else
            echo -e "  ${YELLOW}⚠${NC} nslookup not available for DNS verification"
            WARNINGS=$((WARNINGS + 1))
        fi
        
        # Summary
        echo ""
        echo "======================================"
        if [ $ERRORS -eq 0 ]; then
            if [ $WARNINGS -eq 0 ]; then
                echo -e "${GREEN}✅ All preflight checks passed!${NC}"
            else
                echo -e "${GREEN}✅ Preflight passed with $WARNINGS warnings${NC}"
            fi
            echo ""
            echo "Ready for manual testing:"
            echo "  - Browser: https://postman.co"
            echo "  - Desktop: Open Postman Desktop app"
        else
            echo -e "${RED}❌ Preflight failed with $ERRORS errors, $WARNINGS warnings${NC}"
            echo ""
            echo "Fix errors before testing. Run: sudo $0 setup"
        fi
        echo "======================================"
        ;;
        
    # Backward compatibility - redirect to setup
    demo)
        $0 setup
        ;;
        
    cleanup)
        echo -e "${GREEN}Cleaning up demo environment...${NC}"
        echo "This will remove all traces of the Postman Auth Router"
        echo ""
        
        # 1. Stop daemon (which will also remove hosts entries)
        echo "Stopping daemon and removing hosts entries..."
        $0 stop
        
        # 2. Remove certificate from keychain
        echo ""
        echo "Removing certificate from keychain..."
        if security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null | grep -q "identity.getpostman.com"; then
            security delete-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null || true
            echo -e "  ${GREEN}✓${NC} Certificate removed from keychain"
        else
            echo -e "  ${YELLOW}⚠${NC} Certificate not found in keychain"
        fi
        
        # 4. Remove generated files (keep templates and scripts)
        echo ""
        echo "Removing generated files..."
        if [ -f "ssl/cert.pem" ] || [ -f "ssl/key.pem" ]; then
            rm -f ssl/cert.pem ssl/key.pem ssl/*.crt ssl/*.key ssl/*.csr 2>/dev/null
            echo -e "  ${GREEN}✓${NC} Certificates removed"
        else
            echo -e "  ${YELLOW}⚠${NC} No certificates to remove"
        fi
        
        # 5. Optionally remove config (ask user)
        if [ -f "config/config.json" ]; then
            read -p "Remove config/config.json? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                rm -f config/config.json
                echo -e "  ${GREEN}✓${NC} Config removed"
            else
                echo -e "  ${YELLOW}⚠${NC} Config kept"
            fi
        fi
        
        # 6. Clear DNS cache
        echo ""
        echo "Flushing DNS cache..."
        dscacheutil -flushcache 2>/dev/null || true
        killall -HUP mDNSResponder 2>/dev/null || true
        echo -e "  ${GREEN}✓${NC} DNS cache flushed"
        
        echo ""
        echo "======================================"
        echo -e "${GREEN}✅ Cleanup complete!${NC}"
        echo ""
        echo "The system has been restored to its original state."
        echo "To set up again, run: sudo $0 setup"
        echo "======================================"
        ;;
        
    --help|-h|help|*)
        echo ""
        echo "Postman Auth Router - Enterprise SAML Enforcement"
        echo "================================================="
        echo ""
        echo "Usage: sudo $0 <command>"
        echo ""
        echo -e "${BLUE}Quick Start:${NC}"
        echo "  setup        Complete setup with all configurations"
        echo "  cleanup      Remove all changes and restore system"
        echo ""
        echo -e "${BLUE}Service Management:${NC}"
        echo "  start        Start the authentication daemon"
        echo "  stop         Stop the daemon"
        echo "  restart      Restart the daemon"
        echo "  status       Check daemon status and health"
        echo "  logs         View daemon logs (tail -f)"
        echo ""
        echo -e "${BLUE}Certificate Management:${NC}"
        echo "  cert         Smart certificate management (generate/trust as needed)"
        echo ""
        echo -e "${BLUE}Validation:${NC}"
        echo "  preflight    Run preflight checks before manual testing"
        echo ""
        echo -e "${BLUE}Examples:${NC}"
        echo "  sudo $0 setup       # First time setup"
        echo "  sudo $0 preflight   # Validate configuration"
        echo "  sudo $0 cleanup     # Complete removal"
        echo ""
        echo -e "${BLUE}Testing After Setup:${NC}"
        echo "  Browser:  https://postman.co"
        echo "  Desktop:  Open Postman Desktop app"
        echo ""
        if [ "$EUID" -ne 0 ] && [ "$1" != "--help" ] && [ "$1" != "-h" ] && [ "$1" != "help" ]; then
            echo -e "${YELLOW}Note: Most commands require sudo${NC}"
        fi
        exit 0
        ;;
esac