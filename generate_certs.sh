#!/bin/bash

#############################################################################
# Certificate Generation Script for Postman SAML Authentication Router
# 
# Generates self-signed certificates for development/testing
# For production, use proper certificates from your CA or JAMF
#############################################################################

set -e

# Configuration
CERT_DIR="ssl"
CERT_DAYS=365
HOSTNAME="identity.getpostman.com"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================================================"
echo "     Certificate Generation for Postman Auth Router"
echo "======================================================================"
echo ""

# Create SSL directory if it doesn't exist
if [ ! -d "$CERT_DIR" ]; then
    echo "Creating SSL directory..."
    mkdir -p "$CERT_DIR"
fi

# Check if certificates already exist
if [ -f "$CERT_DIR/cert.pem" ] && [ -f "$CERT_DIR/key.pem" ]; then
    echo -e "${YELLOW}Warning: Certificates already exist in $CERT_DIR/${NC}"
    read -p "Do you want to overwrite them? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Certificate generation cancelled."
        exit 0
    fi
    echo ""
fi

echo "Generating self-signed certificate with SAN for all Postman domains"
echo "Using configuration: $CERT_DIR/cert.conf"
echo "Valid for: $CERT_DAYS days"
echo ""

# Generate private key and certificate using the configuration file
openssl req -new -x509 -days $CERT_DAYS -nodes \
    -out "$CERT_DIR/cert.pem" \
    -keyout "$CERT_DIR/key.pem" \
    -config "$CERT_DIR/cert.conf" \
    -extensions v3_req \
    2>/dev/null

# Set appropriate permissions
chmod 600 "$CERT_DIR/key.pem"
chmod 644 "$CERT_DIR/cert.pem"

echo -e "${GREEN}✓ Certificates generated successfully!${NC}"

# Add certificate to system keychain and trust it (requires sudo)
if [[ $EUID -eq 0 ]]; then
    echo "Adding certificate to system keychain and marking as trusted..."
    
    # Add to system keychain
    security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CERT_DIR/cert.pem"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Certificate added to system keychain and trusted${NC}"
        echo -e "${GREEN}✓ No browser warnings should appear!${NC}"
    else
        echo -e "${YELLOW}⚠ Could not add certificate to keychain (this is optional)${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Not running as root - certificate not added to keychain${NC}"
    echo -e "${YELLOW}  Run with sudo to automatically trust the certificate${NC}"
fi
echo ""
echo "Files created:"
echo "  - $CERT_DIR/cert.pem (Certificate)"
echo "  - $CERT_DIR/key.pem  (Private Key)"
echo ""
echo "======================================================================"
echo "                          IMPORTANT NOTES"
echo "======================================================================"
echo ""
echo "1. These are SELF-SIGNED certificates for development only"
echo "   When run with sudo, they are automatically trusted (no browser warnings)"
echo ""
echo "2. For production deployment:"
echo "   - Use certificates from your enterprise CA"
echo "   - Or export from JAMF certificate management"
echo "   - Or use Let's Encrypt with proper domain validation"
echo ""
echo "3. To use JAMF-managed certificates:"
echo "   a. Export from Keychain Access:"
echo "      security find-certificate -c \"$HOSTNAME\" -p > $CERT_DIR/cert.pem"
echo "      security find-identity -v -p codesigning"
echo ""
echo "   b. Or use JAMF's certificate deployment:"
echo "      See PRODUCTION.md for detailed instructions"
echo ""
echo "4. Certificate files are gitignored for security"
echo "   Never commit private keys to version control!"
echo ""
echo "======================================================================"

exit 0