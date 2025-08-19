#!/bin/bash
# macOS System Proxy Configuration for PAC File Approach
# UNTESTED POC - Requires validation before production use

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAC_FILE="$SCRIPT_DIR/../config/postman.pac"
PAC_URL_FILE="$SCRIPT_DIR/../config/pac_url.txt"

# Check for admin privileges  
check_admin() {
    if [[ $EUID -eq 0 ]]; then
        echo "WARNING: Running as root. Consider running as regular user for system proxy changes."
    fi
}

# Get network service name (usually "Wi-Fi" or "Ethernet")
get_network_service() {
    # Try to detect active network service
    local service=$(networksetup -listnetworkserviceorder | grep -E "(Wi-Fi|Ethernet)" | head -1 | sed 's/.*) //')
    if [[ -z "$service" ]]; then
        echo "Wi-Fi"  # Default fallback
    else
        echo "$service"
    fi
}

# Enable PAC file configuration
enable_pac() {
    local network_service=$(get_network_service)
    local pac_url
    
    echo "Configuring PAC file for network service: $network_service"
    echo "UNTESTED POC - Monitor system network settings"
    
    # Check if PAC URL file exists
    if [[ -f "$PAC_URL_FILE" ]]; then
        pac_url=$(cat "$PAC_URL_FILE")
        echo "Using PAC URL: $pac_url"
    else
        # Generate file URL if not available
        pac_url="file://$(realpath "$PAC_FILE")"
        echo "Generated PAC URL: $pac_url"
    fi
    
    # Configure system to use PAC file
    echo "Setting system proxy configuration..."
    networksetup -setautoproxyurl "$network_service" "$pac_url"
    networksetup -setautoproxystate "$network_service" on
    
    echo "PAC file configuration enabled"
    echo "Network service: $network_service"
    echo "PAC URL: $pac_url"
}

# Disable PAC file configuration
disable_pac() {
    local network_service=$(get_network_service)
    
    echo "Disabling PAC file configuration for: $network_service"
    networksetup -setautoproxystate "$network_service" off
    
    echo "PAC file configuration disabled"
}

# Show current proxy configuration
show_config() {
    local network_service=$(get_network_service)
    
    echo "Current proxy configuration for: $network_service"
    echo "=============================================="
    
    # Show all proxy settings
    networksetup -getautoproxyurl "$network_service"
    
    echo ""
    echo "Full proxy info:"
    networksetup -getproxyinfo "$network_service"
}

# Test PAC file functionality
test_pac() {
    echo "Testing PAC file functionality..."
    echo "UNTESTED POC - Manual verification required"
    
    # Check if PAC file exists
    if [[ ! -f "$PAC_FILE" ]]; then
        echo "ERROR: PAC file not found: $PAC_FILE"
        echo "Run: python3 ../src/generate_pac.py"
        exit 1
    fi
    
    echo "PAC file found: $PAC_FILE"
    echo "Content preview:"
    head -10 "$PAC_FILE"
    
    # Check if proxy daemon is running
    if pgrep -f "saml_proxy_daemon" > /dev/null; then
        echo "Proxy daemon: Running"
    else
        echo "Proxy daemon: Not running"
        echo "Start with: python3 ../src/saml_proxy_daemon.py"
    fi
    
    echo ""
    echo "Manual test steps:"
    echo "1. Verify PAC file is accessible"
    echo "2. Check system proxy settings in System Preferences > Network"
    echo "3. Test with: curl -v https://identity.getpostman.com/login"
    echo "4. Verify proxy receives connection"
}

# Main command processing
case "$1" in
    enable)
        check_admin
        enable_pac
        ;;
    disable)
        check_admin
        disable_pac
        ;;
    status)
        show_config
        ;;
    test)
        test_pac
        ;;
    *)
        echo "macOS PAC Proxy Configuration - UNTESTED POC"
        echo "Usage: $0 {enable|disable|status|test}"
        echo ""
        echo "Commands:"
        echo "  enable   Enable PAC file proxy configuration"
        echo "  disable  Disable PAC file proxy configuration"
        echo "  status   Show current proxy configuration"
        echo "  test     Test PAC file and proxy daemon"
        echo ""
        echo "WARNING: This is an untested proof-of-concept"
        echo "Monitor system behavior and network connectivity"
        exit 1
        ;;
esac