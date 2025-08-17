#!/bin/bash

#############################################################################
# Clear Postman Sessions Script
# 
# Removes Postman session cookies from all browsers and desktop client
# Useful for testing authentication flow and rollout scenarios
#############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================================================"
echo "     Clearing All Postman Sessions"
echo "========================================================================"
echo ""
echo -e "${YELLOW}⚠️  This will log you out of Postman everywhere${NC}"
echo ""

# Function to clear Safari cookies
clear_safari() {
    echo "Clearing Safari Postman cookies..."
    
    # Safari stores cookies in a binary plist file
    if [ -f ~/Library/Cookies/Cookies.binarycookies ]; then
        # We can't directly edit binary cookies, but we can use defaults to clear specific domains
        osascript -e 'tell application "Safari" to quit' 2>/dev/null || true
        
        # Remove Postman-related cookies from Safari's cookie storage
        sqlite3 ~/Library/Safari/Databases/safari-cookies.db \
            "DELETE FROM cookies WHERE domain LIKE '%postman.com%';" 2>/dev/null || true
        
        echo -e "${GREEN}✓ Safari cookies cleared${NC}"
    else
        echo "Safari cookies not found or not accessible"
    fi
}

# Function to clear Chrome cookies
clear_chrome() {
    echo "Clearing Chrome Postman cookies..."
    
    # Chrome stores cookies in SQLite database
    CHROME_COOKIES="$HOME/Library/Application Support/Google/Chrome/Default/Cookies"
    if [ -f "$CHROME_COOKIES" ]; then
        # Quit Chrome first
        osascript -e 'tell application "Google Chrome" to quit' 2>/dev/null || true
        sleep 2
        
        # Delete Postman cookies from Chrome's SQLite database
        sqlite3 "$CHROME_COOKIES" \
            "DELETE FROM cookies WHERE host_key LIKE '%postman.com%';" 2>/dev/null || {
            echo "Chrome is running or database is locked. Please close Chrome and try again."
        }
        
        echo -e "${GREEN}✓ Chrome cookies cleared${NC}"
    else
        echo "Chrome cookies database not found"
    fi
}

# Function to clear Firefox cookies
clear_firefox() {
    echo "Clearing Firefox Postman cookies..."
    
    # Firefox stores cookies in SQLite database in profile folder
    FIREFOX_PROFILES="$HOME/Library/Application Support/Firefox/Profiles"
    if [ -d "$FIREFOX_PROFILES" ]; then
        # Quit Firefox first
        osascript -e 'tell application "Firefox" to quit' 2>/dev/null || true
        sleep 2
        
        # Find all Firefox profiles and clear cookies
        for profile in "$FIREFOX_PROFILES"/*.default*; do
            if [ -f "$profile/cookies.sqlite" ]; then
                sqlite3 "$profile/cookies.sqlite" \
                    "DELETE FROM moz_cookies WHERE host LIKE '%postman.com%';" 2>/dev/null || {
                    echo "Firefox is running or database is locked. Please close Firefox and try again."
                }
            fi
        done
        
        echo -e "${GREEN}✓ Firefox cookies cleared${NC}"
    else
        echo "Firefox profiles not found"
    fi
}

# Function to clear Edge cookies
clear_edge() {
    echo "Clearing Edge Postman cookies..."
    
    # Edge uses similar structure to Chrome
    EDGE_COOKIES="$HOME/Library/Application Support/Microsoft Edge/Default/Cookies"
    if [ -f "$EDGE_COOKIES" ]; then
        # Quit Edge first
        osascript -e 'tell application "Microsoft Edge" to quit' 2>/dev/null || true
        sleep 2
        
        # Delete Postman cookies from Edge's SQLite database
        sqlite3 "$EDGE_COOKIES" \
            "DELETE FROM cookies WHERE host_key LIKE '%postman.com%';" 2>/dev/null || {
            echo "Edge is running or database is locked. Please close Edge and try again."
        }
        
        echo -e "${GREEN}✓ Edge cookies cleared${NC}"
    else
        echo "Edge cookies database not found"
    fi
}

# Function to clear Postman Desktop App data
clear_postman_desktop() {
    echo "Clearing Postman Desktop App session..."
    
    # Postman Desktop stores data in multiple locations
    POSTMAN_APP_SUPPORT="$HOME/Library/Application Support/Postman"
    POSTMAN_PREFERENCES="$HOME/Library/Preferences/com.postmanlabs.mac.plist"
    
    # Quit Postman first
    osascript -e 'tell application "Postman" to quit' 2>/dev/null || true
    sleep 2
    
    # Clear Postman session storage
    if [ -d "$POSTMAN_APP_SUPPORT" ]; then
        # Remove session-related files but keep workspace data
        rm -rf "$POSTMAN_APP_SUPPORT/proxy" 2>/dev/null || true
        rm -rf "$POSTMAN_APP_SUPPORT/Cache" 2>/dev/null || true
        rm -rf "$POSTMAN_APP_SUPPORT/CachedData" 2>/dev/null || true
        rm -rf "$POSTMAN_APP_SUPPORT/cookies" 2>/dev/null || true
        rm -rf "$POSTMAN_APP_SUPPORT/Session Storage" 2>/dev/null || true
        rm -rf "$POSTMAN_APP_SUPPORT/Local Storage" 2>/dev/null || true
        
        echo -e "${GREEN}✓ Postman Desktop session cleared${NC}"
    else
        echo "Postman Desktop data not found"
    fi
}

# Function to clear system keychain Postman items (optional)
clear_keychain() {
    echo "Checking for Postman entries in system keychain..."
    
    # List Postman-related keychain items
    security find-internet-password -s "postman.com" 2>/dev/null | grep "postman.com" > /dev/null 2>&1 && {
        echo -e "${YELLOW}Found Postman entries in keychain${NC}"
        read -p "Clear keychain entries too? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            security delete-internet-password -s "postman.com" 2>/dev/null || true
            security delete-internet-password -s "identity.getpostman.com" 2>/dev/null || true
            echo -e "${GREEN}✓ Keychain entries cleared${NC}"
        fi
    } || {
        echo "No Postman keychain entries found"
    }
}

# Main execution
echo "Starting session cleanup..."
echo ""

# Clear browser cookies
clear_safari
clear_chrome
clear_firefox
clear_edge

echo ""

# Clear Postman Desktop
clear_postman_desktop

echo ""

# Optionally clear keychain
clear_keychain

echo ""
echo "========================================================================"
echo -e "${GREEN}✅ Session cleanup complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Visit https://identity.getpostman.com to test authentication"
echo "2. You should be redirected to your IDP for login"
echo "3. After auth, you'll have a fresh Postman session"
echo ""
echo "========================================================================"

exit 0