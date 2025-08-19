#!/bin/bash
# Postman SAML Daemon Manager

set -e

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo "Run with sudo"
    exit 1
fi

# Hosts management
add_hosts() {
    if ! grep -q "127.0.0.1 identity.getpostman.com" /etc/hosts; then
        cp /etc/hosts /etc/hosts.backup
        echo "127.0.0.1 identity.getpostman.com" >> /etc/hosts
        echo "Added hosts entry"
    fi
}

remove_hosts() {
    if grep -q "127.0.0.1 identity.getpostman.com" /etc/hosts; then
        cp /etc/hosts /etc/hosts.backup
        sed -i.bak '/127\.0\.0\.1.*identity\.getpostman\.com/d' /etc/hosts
        echo "Removed hosts entry"
    fi
}

case "$1" in
    start)
        echo "Starting daemon..."
        
        # Handle SSL certificates FIRST (before modifying hosts)
        CERT_DIR="ssl"
        CERT_FILE="$CERT_DIR/cert.pem"
        KEY_FILE="$CERT_DIR/key.pem"
        CERT_DAYS=365
        
        # Check if certificates exist
        if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
            echo "Generating SSL certificates..."
            
            # Create SSL directory if needed
            if [ ! -d "$CERT_DIR" ]; then
                mkdir -p "$CERT_DIR"
            fi
            
            # Check for cert.conf
            if [ ! -f "$CERT_DIR/cert.conf" ]; then
                echo "Error: Certificate configuration not found at $CERT_DIR/cert.conf"
                echo "This file is required for certificate generation"
                exit 1
            fi
            
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
                echo "Certificates generated successfully"
            else
                echo "Certificate generation failed"
                exit 1
            fi
        fi
        
        # Trust the certificate if not already trusted (domain-specific, NOT root CA)
        if ! security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null | grep -q "identity.getpostman.com"; then
            echo "Adding certificate to system keychain..."
            security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain "$CERT_FILE"
            echo "Certificate trusted"
        fi
        
        # Add hosts entries AFTER certificates are ready
        add_hosts
        
        pkill -f "saml_enforcer" 2>/dev/null || true
        lsof -ti:443 | xargs kill -9 2>/dev/null || true
        sleep 1
        python3 src/saml_enforcer.py &
        sleep 2
        if pgrep -f "saml_enforcer" > /dev/null; then
            echo "Started"
        else
            echo "Failed to start"
            remove_hosts
            exit 1
        fi
        ;;
    stop)
        echo "Stopping daemon..."
        pkill -f "saml_enforcer" 2>/dev/null || true
        remove_hosts
        echo "Stopped"
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    status)
        if pgrep -f "saml_enforcer" > /dev/null; then
            echo "Running"
        else
            echo "Not running"
        fi
        ;;
    *)
        echo "Usage: sudo $0 {start|stop|restart|status}"
        exit 1
        ;;
esac