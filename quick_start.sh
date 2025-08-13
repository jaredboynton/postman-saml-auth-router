#!/bin/bash

#############################################################################
# Postman SAML Authentication Router - Quick Start (Development/Testing)
#############################################################################

set -e

echo "======================================================================"
echo "     Postman SAML Auth Router - Quick Start"
echo "======================================================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Kill any existing daemon
echo "Stopping any existing daemon..."
pkill -f "auth_router_final.py" 2>/dev/null || true

# Add hosts entry
echo "Adding hosts entry..."
grep -q "identity.getpostman.com" /etc/hosts || echo "127.0.0.1 identity.getpostman.com" >> /etc/hosts

# Flush DNS
echo "Flushing DNS cache..."
dscacheutil -flushcache 2>/dev/null || true

# Start daemon
echo "Starting daemon..."
echo ""
echo "======================================================================"
echo "Daemon starting on https://127.0.0.1:443"
echo "Press Ctrl+C to stop"
echo "======================================================================"
echo ""

python3 src/auth_router_final.py config/config.json