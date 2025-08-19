#!/bin/bash
# Zscaler Client Connector POC Management Script - macOS Only
# 
# PROOF OF CONCEPT: Demonstrates how Zscaler Client Connector could 
# implement device-level SAML enforcement using PAC files and local
# proxy agents without hosts file modification.

set -e

cd "$(dirname "$0")/.."

echo "Zscaler Client Connector POC - SAML Enforcement Demo"
echo "===================================================="
echo "POC Purpose: Demonstrate Zscaler agent device-level"
echo "proxy routing for Postman SAML enforcement"
echo ""

case "$1" in
    start)
        echo "Starting Zscaler Client Connector POC..."
        echo ""
        
        # Generate PAC file
        echo "1. Generating Zscaler PAC file..."
        python3 src/generate_zscaler_pac.py
        
        # Start proxy agent
        echo ""
        echo "2. Starting Zscaler SAML agent on port 8444..."
        python3 src/zscaler_saml_agent.py --config config/config.json.template &
        DAEMON_PID=$!
        echo "Proxy daemon started (PID: $DAEMON_PID)"
        
        # Configure system proxy
        echo ""
        echo "3. Configuring system proxy (requires admin for networksetup)..."
        sudo scripts/configure_zscaler_mac.sh enable
        
        echo ""
        echo "Zscaler Client Connector POC started successfully"
        echo "Demonstration: Zscaler Client Connector could:"
        echo "- Deploy PAC files via Zscaler cloud policy"
        echo "- Run local SAML enforcement agents"
        echo "- Configure device proxy settings automatically"
        echo "- No hosts file modification required"
        ;;
        
    stop)
        echo "Stopping Zscaler Client Connector POC..."
        
        # Stop proxy agent
        pkill -f "zscaler_saml_agent" 2>/dev/null || true
        echo "Zscaler SAML agent stopped"
        
        # Disable system proxy
        echo "Disabling system proxy configuration..."
        sudo scripts/configure_zscaler_mac.sh disable
        
        echo "Zscaler Client Connector POC stopped"
        ;;
        
    status)
        echo "Zscaler Client Connector POC Status:"
        echo "===================================="
        
        # Check proxy agent
        if pgrep -f "zscaler_saml_agent" > /dev/null; then
            echo "Zscaler SAML agent: Running"
        else
            echo "Zscaler SAML agent: Not running"
        fi
        
        # Check PAC file
        if [[ -f "config/postman.pac" ]]; then
            echo "Zscaler PAC file: Generated"
        else
            echo "Zscaler PAC file: Not generated"
        fi
        
        # Check system proxy config
        echo ""
        echo "System proxy configuration:"
        scripts/configure_zscaler_mac.sh status
        ;;
        
    test)
        echo "Testing PAC Proxy POC..."
        echo "======================="
        echo ""
        
        # Test components
        scripts/configure_proxy_mac.sh test
        
        echo ""
        echo "Enterprise Agent Implications:"
        echo "- Zscaler Client Connector could deploy similar PAC logic"
        echo "- Device-level proxy routing without system modification"
        echo "- Centrally managed via cloud policy"
        echo "- Same SSL termination capabilities demonstrated here"
        ;;
        
    generate-cert)
        echo "Generating certificates for PAC Proxy POC..."
        cd ssl
        openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out cert.csr \
            -config cert.conf -extensions req_ext
        openssl x509 -req -in cert.csr -signkey key.pem -out cert.pem \
            -days 365 -extensions req_ext -extfile cert.conf
        rm cert.csr
        echo "Certificates generated in ssl/"
        echo ""
        echo "Note: Enterprise agents would use corporate CA certificates"
        ;;
        
    *)
        echo "Usage: $0 {start|stop|status|test|generate-cert}"
        echo ""
        echo "PAC Proxy POC - Enterprise Agent Demonstration"
        echo ""
        echo "Commands:"
        echo "  start         Start PAC proxy POC (generates PAC, starts daemon, configures proxy)"
        echo "  stop          Stop PAC proxy POC (stops daemon, disables proxy)"
        echo "  status        Check POC component status"
        echo "  test          Test POC functionality and show enterprise implications"
        echo "  generate-cert Generate SSL certificates for proxy"
        echo ""
        echo "PURPOSE: Proof-of-concept demonstrating how enterprise proxy agents"
        echo "like Zscaler Client Connector could implement device-level SAML"
        echo "enforcement using PAC files instead of hosts file modification."
        echo ""
        echo "ENTERPRISE AGENT BENEFITS:"
        echo "- No hosts file modification required"
        echo "- Standard proxy configuration methods"
        echo "- Centrally managed via cloud policies"
        echo "- Same SSL termination and inspection capabilities"
        echo "- Device-level enforcement without network infrastructure changes"
        exit 1
        ;;
esac