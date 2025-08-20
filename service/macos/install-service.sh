#!/bin/bash
# Postman SAML Enforcer macOS Service Installer
# Requires Administrator privileges (sudo)

set -e

# Auto-detect project structure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Validate project structure
if [[ ! -f "$PROJECT_ROOT/src/saml_enforcer.py" ]]; then
    echo "Error: Could not locate project structure from script location"
    echo "Expected to find: $PROJECT_ROOT/src/saml_enforcer.py"
    exit 1
fi

# Configuration
SERVICE_NAME="com.postman.saml-enforcer"
SERVICE_PLIST="com.postman.saml-enforcer.plist"
INSTALL_DIR="/usr/local/postman-saml-enforcer"
PLIST_SOURCE="$SCRIPT_DIR/$SERVICE_PLIST"
PLIST_DEST="/Library/LaunchDaemons/$SERVICE_PLIST"
DAEMON_SCRIPT="$PROJECT_ROOT/src/saml_enforcer.py"

# Output functions

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Administrator privileges required. Please run with sudo."
    exit 1
fi

# Validate action parameter
if [ $# -eq 0 ]; then
    echo "Usage: sudo $0 {install|uninstall|start|stop|status|srefresh}"
    echo ""
    echo "Actions:"
    echo "  install   - Install service for permanent deployment"
    echo "  start     - Start daemon (installs as service if not already installed)"
    echo "  stop      - Stop service or daemon"
    echo "  status    - Show service or daemon status"
    echo "  srefresh  - Clear all Postman sessions (browsers & applications)"
    echo "  uninstall - Remove all traces (service, daemon, certificates, hosts)"
    exit 1
fi

ACTION="$1"

# Helper functions
log_info() {
    echo "[INFO] $1"
}

log_warn() {
    echo "[WARN] $1"
}

log_error() {
    echo "[ERROR] $1"
}

# Install Python3 if not available
install_python() {
    log_info "Python3 not found. Installing..."
    
    if command -v brew >/dev/null 2>&1; then
        # macOS with Homebrew
        brew install python3
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS without Homebrew - install Homebrew first
        log_info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        brew install python3
    else
        log_error "This script is for macOS only. Please install Python3 manually."
        exit 1
    fi
    
    log_info "Python3 installed successfully"
}

# Check for Python3 or install it
check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        install_python
    fi
}

# Check if daemon processes are running via daemon_manager.sh
check_daemon_conflicts() {
    if pgrep -f "saml_enforcer" > /dev/null; then
        log_info "Found running daemon processes, stopping automatically..."
        
        # Stop existing daemon processes automatically
        pkill -f "saml_enforcer" 2>/dev/null || true
        sleep 2
    fi
}

# Install service
install_service() {
    log_info "Installing Postman SAML Enforcer service..."
    
    # Check for conflicts
    check_daemon_conflicts
    check_python
    
    # Stop and unload existing service if it exists
    if [ -f "$PLIST_DEST" ]; then
        log_warn "Service already exists. Stopping and removing..."
        launchctl unload "$PLIST_DEST" 2>/dev/null || true
        rm -f "$PLIST_DEST"
        sleep 2
    fi
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    
    # Copy entire project to installation directory
    log_info "Copying project files to $INSTALL_DIR..."
    cp -R "$PROJECT_ROOT/" "$INSTALL_DIR/"
    
    # Set proper ownership and permissions
    chown -R root:wheel "$INSTALL_DIR"
    chmod -R 755 "$INSTALL_DIR"
    chmod 644 "$INSTALL_DIR/$PLIST_SOURCE"
    
    # Copy plist to system location
    log_info "Installing service plist..."
    cp "$INSTALL_DIR/$PLIST_SOURCE" "$PLIST_DEST"
    chown root:wheel "$PLIST_DEST"
    chmod 644 "$PLIST_DEST"
    
    # Load service
    log_info "Loading service..."
    launchctl load "$PLIST_DEST"
    
    # Verify installation
    sleep 3
    if launchctl list | grep -q "$SERVICE_NAME"; then
        log_info "Service installed and loaded successfully"
        log_info "Service will start automatically on boot"
    else
        log_error "Service installation failed"
        exit 1
    fi
}

# Uninstall service
uninstall_service() {
    log_info "Uninstalling Postman SAML Enforcer service..."
    
    # Stop and unload service if it exists
    if launchctl list | grep -q "$SERVICE_NAME"; then
        log_info "Stopping and unloading service..."
        launchctl stop "$SERVICE_NAME" 2>/dev/null || true
        sleep 2
        launchctl unload "$PLIST_DEST" 2>/dev/null || true
        sleep 1
    fi
    
    # Remove service plist
    if [ -f "$PLIST_DEST" ]; then
        log_info "Removing service plist..."
        rm -f "$PLIST_DEST"
    fi
    
    # Stop any running daemon processes
    log_info "Stopping daemon processes..."
    pkill -f "saml_enforcer" 2>/dev/null || true
    
    # Remove hosts file entries
    log_info "Cleaning up hosts file..."
    if grep -q "127.0.0.1 identity.getpostman.com" /etc/hosts 2>/dev/null; then
        cp /etc/hosts /etc/hosts.backup
        sed -i.bak '/127\.0\.0\.1.*identity\.getpostman\.com/d' /etc/hosts
        log_info "Removed hosts file entries"
    fi
    
    # Remove trusted certificates from system keychain
    log_info "Removing trusted certificates..."
    if security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null | grep -q "identity.getpostman.com"; then
        # Remove certificate by common name
        security delete-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null || true
        log_info "Removed certificate from system keychain"
    fi
    
    # Clean up SSL certificate files in install directory
    if [ -d "$INSTALL_DIR" ]; then
        log_info "Cleaning up installation directory..."
        rm -rf "$INSTALL_DIR"
        log_info "Removed installation directory: $INSTALL_DIR"
    fi
    
    # Clean up SSL certificate files in current directory (development)
    if [ -d "ssl" ]; then
        log_info "Cleaning up SSL certificate files..."
        rm -f ssl/cert.pem ssl/key.pem ssl/cert.conf 2>/dev/null || true
        # Remove directory if empty
        if [ ! "$(ls -A ssl 2>/dev/null)" ]; then
            rmdir ssl 2>/dev/null || true
            log_info "Removed empty certificate directory"
        fi
    fi
    
    # Clean up service logs
    log_info "Cleaning up service logs..."
    rm -f /var/log/postman-saml-enforcer*.log 2>/dev/null || true
    
    log_info "Service uninstalled successfully"
}

# Test daemon (direct execution without service installation)
test_daemon() {
    log_info "Starting Postman SAML Enforcer in test mode..."
    
    # Check for conflicts and prerequisites
    check_daemon_conflicts
    check_python
    
    # Verify we have the daemon script
    if [ ! -f "$DAEMON_SCRIPT" ]; then
        log_error "Daemon script not found: $DAEMON_SCRIPT"
        log_error "Project structure validation failed"
        exit 1
    fi
    
    # Start daemon in background (similar to daemon_manager.sh)
    log_info "Starting daemon process..."
    python3 "$DAEMON_SCRIPT" &
    DAEMON_PID=$!
    
    # Wait for daemon to initialize
    sleep 3
    
    # Check if daemon process is running
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        log_error "Daemon failed to start - checking for port conflicts..."
        LOCALHOST_443=$(netstat -an | grep "127.0.0.1:443.*LISTEN" || true)
        if [ -n "$LOCALHOST_443" ]; then
            log_error "Another process is using 127.0.0.1:443"
            log_error "Port conflict detected: $LOCALHOST_443"
        fi
        exit 1
    fi
    
    # Verify daemon is actually running
    if pgrep -f "saml_enforcer" > /dev/null; then
        log_info "Test daemon started successfully (PID: $DAEMON_PID)"
        log_info "Daemon is running in test mode - not installed as system service"
        log_info "Use 'sudo $0 stop' to stop the test daemon"
    else
        log_error "Failed to start test daemon"
        exit 1
    fi
}

# Start service
start_service() {
    if [ -f "$PLIST_DEST" ]; then
        # Service is installed - use normal service start
        log_info "Starting Postman SAML Enforcer service..."
        
        launchctl start "$SERVICE_NAME"
        sleep 2
        
        if launchctl list "$SERVICE_NAME" 2>/dev/null | grep -q '"PID"'; then
            log_info "Service started successfully"
        else
            log_error "Failed to start service"
            exit 1
        fi
    else
        # Service not installed - fall back to test mode
        log_warn "Service not installed. Starting in test mode..."
        log_info "For permanent deployment, run: sudo $0 install"
        test_daemon
    fi
}

# Stop service  
stop_service() {
    log_info "Stopping Postman SAML Enforcer..."
    
    # Check for installed service first
    if launchctl list | grep -q "$SERVICE_NAME"; then
        launchctl stop "$SERVICE_NAME"
        log_info "Service stopped successfully"
    elif pgrep -f "saml_enforcer" > /dev/null; then
        # Stop test daemon processes
        log_info "Stopping test daemon processes..."
        pkill -f "saml_enforcer" 2>/dev/null || true
        sleep 1
        
        if ! pgrep -f "saml_enforcer" > /dev/null; then
            log_info "Test daemon stopped successfully"
        else
            log_warn "Some daemon processes may still be running"
        fi
    else
        log_warn "No service or daemon processes running"
    fi
}


# Get service status
get_service_status() {
    local has_service=false
    local has_daemon=false
    
    # Check for installed service
    if [ -f "$PLIST_DEST" ]; then
        has_service=true
        echo "=== Service Status ==="
        
        if launchctl list "$SERVICE_NAME" 2>/dev/null | grep -q '"PID"'; then
            local pid=$(launchctl list "$SERVICE_NAME" | grep '"PID"' | awk '{print $3}' | tr -d ',')
            echo "Service Status: Running (PID: $pid)"
            echo "Auto-start: Enabled"
        else
            echo "Service Status: Stopped"
            echo "Auto-start: Enabled"
        fi
    fi
    
    # Check for test daemon processes
    if pgrep -f "saml_enforcer" > /dev/null; then
        has_daemon=true
        local daemon_pids=$(pgrep -f "saml_enforcer" | tr '\n' ' ')
        
        if [ "$has_service" = true ]; then
            echo ""
            echo "=== Test Daemon Status ==="
        else
            echo "=== Daemon Status ==="
        fi
        
        echo "Test Daemon: Running (PID(s): $daemon_pids)"
        echo "Mode: Direct execution (not installed as service)"
    fi
    
    # Summary if nothing is running
    if [ "$has_service" = false ] && [ "$has_daemon" = false ]; then
        echo "Service: Not installed"
        echo "Daemon: Not running"
        echo ""
        echo "To start: sudo $0 start"
        echo "To install as service: sudo $0 install"
    fi
}

# Clear Postman sessions
clear_postman_sessions() {
    log_info "Clearing all Postman authentication sessions..."
    
    # Check Python is available
    check_python
    
    # Path to the session clearing script
    SESSION_SCRIPT="$PROJECT_ROOT/scripts/clear_postman_sessions.py"
    
    if [ ! -f "$SESSION_SCRIPT" ]; then
        log_error "Session clearing script not found: $SESSION_SCRIPT"
        log_error "Project structure validation failed"
        exit 1
    fi
    
    # Run the session clearing script
    log_info "Running session clearing script..."
    python3 "$SESSION_SCRIPT"
    
    if [ $? -eq 0 ]; then
        log_info "Session clearing completed successfully"
        log_info "All Postman authentication sessions have been cleared"
    else
        log_warn "Session clearing completed with warnings"
        log_info "Core session clearing functionality completed"
    fi
}


# Main execution
case "$ACTION" in
    install)
        install_service
        ;;
    uninstall)
        uninstall_service
        ;;
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    status)
        get_service_status
        ;;
    srefresh)
        clear_postman_sessions
        ;;
    *)
        echo "Usage: sudo $0 {install|uninstall|start|stop|status|srefresh}"
        echo ""
        echo "Actions:"
        echo "  install   - Install service for permanent deployment"
        echo "  start     - Start daemon (test mode if not installed)"
        echo "  stop      - Stop service or daemon"
        echo "  status    - Show service or daemon status"
        echo "  srefresh  - Clear all Postman sessions (browsers & applications)"
        echo "  uninstall - Remove all traces (service, daemon, certificates, hosts)"
        exit 1
        ;;
esac