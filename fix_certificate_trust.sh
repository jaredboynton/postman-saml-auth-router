#!/bin/bash
# Fix certificate trust issue for Postman authentication interception

echo "Fixing SSL certificate trust settings..."
echo "This will properly trust the certificate for SSL connections"

# Remove existing certificate first (if any)
echo "Removing any existing certificate..."
sudo security delete-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null || true

# Add certificate with proper trust settings
echo "Adding certificate with SSL trust..."
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ssl/cert.pem

# Verify trust settings
echo ""
echo "Verifying trust settings..."
security dump-trust-settings -d | grep -A5 "identity.getpostman.com"

echo ""
echo "Testing HTTPS connection..."
curl -v https://identity.getpostman.com/test 2>&1 | grep -E "(Connected to|SSL connection|HTTP/)"

echo ""
echo "Certificate trust fixed! You should now be able to:"
echo "1. Navigate to https://identity.getpostman.com in your browser"
echo "2. Sign in with Postman Desktop"