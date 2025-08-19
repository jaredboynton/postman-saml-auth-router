#!/bin/bash
# DNS Interceptor POC Management Script

set -e

cd "$(dirname "$0")/.."

case "$1" in
    start)
        echo "Starting DNS Interceptor POC..."
        echo "Note: Requires admin privileges for DNS server on port 53"
        echo "TODO: Start DNS server component"
        echo "Starting SAML daemon on port 8443..."
        python3 src/saml_enforcer.py --config config/config.json.template &
        echo "DNS Interceptor POC started"
        ;;
    stop)
        echo "Stopping DNS Interceptor POC..."
        pkill -f "saml_enforcer" 2>/dev/null || true
        echo "TODO: Stop DNS server component"
        echo "DNS Interceptor POC stopped"
        ;;
    status)
        if pgrep -f "saml_enforcer" > /dev/null; then
            echo "SAML daemon: Running"
        else
            echo "SAML daemon: Not running"
        fi
        echo "TODO: Check DNS server status"
        ;;
    generate-cert)
        echo "Generating certificates for DNS Interceptor POC..."
        cd ssl
        openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out cert.csr \
            -config cert.conf -extensions req_ext
        openssl x509 -req -in cert.csr -signkey key.pem -out cert.pem \
            -days 365 -extensions req_ext -extfile cert.conf
        rm cert.csr
        echo "Certificates generated in ssl/"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|generate-cert}"
        echo ""
        echo "DNS Interceptor POC - Local DNS server approach"
        echo "  start         Start DNS server and daemon"
        echo "  stop          Stop DNS server and daemon"  
        echo "  status        Check component status"
        echo "  generate-cert Generate SSL certificates"
        exit 1
        ;;
esac