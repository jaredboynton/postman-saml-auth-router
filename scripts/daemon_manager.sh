#!/bin/bash

set -e
if [ "$EUID" -ne 0 ]; then 
    echo "Run with sudo"
    exit 1
fi

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
        
        CERT_DIR="ssl"
        CERT_FILE="$CERT_DIR/cert.pem"
        KEY_FILE="$CERT_DIR/key.pem"
        CERT_DAYS=365
        
        if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
            echo "Generating SSL certificates..."
            
            if [ ! -d "$CERT_DIR" ]; then
                mkdir -p "$CERT_DIR"
            fi
            
            if [ ! -f "$CERT_DIR/cert.conf" ]; then
                echo "Error: Certificate configuration not found at $CERT_DIR/cert.conf"
                echo "This file is required for certificate generation"
                exit 1
            fi
            
            openssl req -new -x509 -days $CERT_DAYS -nodes \
                -out "$CERT_FILE" \
                -keyout "$KEY_FILE" \
                -config "$CERT_DIR/cert.conf" \
                -extensions v3_req 2>/dev/null
            
            if [ $? -eq 0 ]; then
                chmod 600 "$KEY_FILE"
                chmod 644 "$CERT_FILE"
                echo "Certificates generated successfully"
            else
                echo "Certificate generation failed"
                exit 1
            fi
        fi
        
        if ! security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null | grep -q "identity.getpostman.com"; then
            echo "Adding certificate to system keychain..."
            security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain "$CERT_FILE"
            echo "Certificate trusted"
        fi
        
        add_hosts
        
        pkill -f "saml_enforcer" 2>/dev/null || true
        sleep 1
        
        # Try to start daemon first
        python3 src/saml_enforcer.py &
        sleep 2
        
        # Check if daemon started successfully
        if pgrep -f "saml_enforcer" > /dev/null; then
            echo "Started"
        else
            echo "Daemon failed to start - checking for port conflicts..."
            # Only now check for processes that might be conflicting
            LOCALHOST_443=$(netstat -an | grep "127.0.0.1:443.*LISTEN" || true)
            if [ -n "$LOCALHOST_443" ]; then
                echo "Another process is using 127.0.0.1:443"
                echo "Port conflict detected: $LOCALHOST_443"
            fi
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