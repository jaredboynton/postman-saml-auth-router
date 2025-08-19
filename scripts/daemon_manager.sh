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