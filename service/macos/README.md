# macOS Service Deployment Guide

Postman SAML Enforcer - macOS LaunchDaemon Installation

## Overview

This directory contains the automated installation system for deploying the Postman SAML Enforcer as a persistent macOS system service using LaunchDaemon.

The service automatically:
- Starts on system boot
- Restarts on crashes or unexpected exits
- Runs with root privileges
- Manages SSL certificates and system trust
- Maintains hosts file entries
- Provides comprehensive logging

## Quick Start

```bash
# Install and start service
sudo service/macos/install-service.sh install

# Check service status
sudo service/macos/install-service.sh status

# Stop service
sudo service/macos/install-service.sh stop

# Clear all Postman sessions (browsers & applications)
sudo service/macos/install-service.sh srefresh

# Complete removal (service, certificates, hosts entries, logs)
sudo service/macos/install-service.sh uninstall
```

## Prerequisites

**Required Privileges:**
- Root access (sudo) for system service installation
- Port 443 binding capability
- System keychain modification rights

**Dependencies:**
- Python 3 (automatically installed - installs Homebrew first if needed, then Python 3)
- OpenSSL (included with macOS)

## Installation Options

### Production Installation

Installs as persistent system service with automatic startup:

```bash
sudo service/macos/install-service.sh install
```

**What this does:**
1. Installs Python 3 if missing (via Homebrew)
2. Copies application to `/usr/local/postman-saml-enforcer`
3. Sets proper ownership and permissions
4. Installs LaunchDaemon plist to `/Library/LaunchDaemons/`
5. Loads and starts the service
6. Service starts automatically on boot

### Test Mode

Runs daemon directly without service installation:

```bash
sudo service/macos/install-service.sh start
```

If no service is installed, automatically starts in test mode:
- Runs daemon process directly
- Good for testing and development
- Must stop manually (does not auto-restart)

## Service Management

### Status Check

```bash
sudo service/macos/install-service.sh status
```

Shows:
- Service installation status
- Running process information
- Auto-start configuration
- Test daemon processes (if any)

### Start/Stop Service

```bash
# Start service
sudo service/macos/install-service.sh start

# Stop service  
sudo service/macos/install-service.sh stop
```

### Advanced macOS Service Commands

```bash
# Check if service is loaded
sudo launchctl list | grep com.postman.saml-enforcer

# Manual service control
sudo launchctl start com.postman.saml-enforcer
sudo launchctl stop com.postman.saml-enforcer

# Reload service configuration
sudo launchctl unload /Library/LaunchDaemons/com.postman.saml-enforcer.plist
sudo launchctl load /Library/LaunchDaemons/com.postman.saml-enforcer.plist
```

## Session Management

### Clear Postman Sessions

The `srefresh` command provides comprehensive session clearing to ensure fresh SAML authentication:

```bash
sudo service/macos/install-service.sh srefresh
```

**What this does:**
1. **Detects Running Applications:** Finds Postman and Postman Enterprise processes
2. **Graceful Application Shutdown:** Quits applications using macOS AppleScript
3. **Browser Cookie Clearing:**
   - **Safari:** Binary cookie file parsing and domain-specific clearing
   - **Chrome:** Direct SQLite database manipulation
   - **Firefox:** Process termination, cookie database cleaning, auto-restart
   - **Brave:** Chromium-based cookie database cleaning
4. **Application Session Files:** Removes `userPartitionData.json` from both Postman apps
5. **Process Restart:** Automatically restarts applications that were originally running

**Targeted Cookie Domains:**
- Core Postman domains (.postman.com, .getpostman.com)
- Authentication domains (identity.postman.com, id.gw.postman.com)  
- Legacy domains (.postman.co, god.postman.co)
- CDN and security cookies (Cloudflare, analytics)

**Business Domain Preservation:**
The session cleaner is designed to preserve business-critical cookies (Salesforce, Okta, Looker, etc.) while targeting only Postman authentication domains.

**When to use:**
- Initial deployment to ensure fresh SAML authentication
- After SAML configuration changes
- When users report cached authentication issues
- Regular maintenance to enforce authentication policies

## Complete Removal

```bash
sudo service/macos/install-service.sh uninstall
```

**Removes all traces:**
- Stops and unloads LaunchDaemon service
- Removes service plist from system
- Stops any running daemon processes
- Removes hosts file entries for identity.getpostman.com
- Removes trusted certificates from System Keychain
- Deletes installation directory
- Cleans up SSL certificate files
- Removes service logs

## Service Configuration

**Service File:** `/Library/LaunchDaemons/com.postman.saml-enforcer.plist`

**Key Features:**
- Runs as root:wheel for proper privileges
- Automatic restart on crashes (`KeepAlive.Crashed=true`)
- Restart on unexpected exit (`KeepAlive.SuccessfulExit=false`)
- 10-second throttle interval prevents rapid restart loops
- Resource limits for security
- Proper environment variable setup

**Installation Directory:** `/usr/local/postman-saml-enforcer`

**Network Configuration:**
- Listens on 127.0.0.1:443 (localhost only, port 443 required for browser compatibility)
- Proxies to real identity.getpostman.com

## Configuration

### Configuration File Setup

The daemon requires a configuration file at `config/config.json` in the project directory:

```json
{
  "postman_team_name": "your-company-team",
  "saml_init_url": "https://identity.getpostman.com/sso/okta/your-tenant-id/init"
}
```

### Required Parameters

- **`postman_team_name`**: Your Postman team identifier (as in your-team.postman.co)
- **`saml_init_url`**: SAML initialization URL for your identity provider

### Optional Parameters

```json
{
  "postman_team_name": "your-company-team",
  "saml_init_url": "https://identity.getpostman.com/sso/okta/your-tenant-id/init",
  "dns_servers": ["8.8.8.8", "1.1.1.1"],
  "ssl_cert": "ssl/cert.pem",
  "ssl_key": "ssl/key.pem"
}
```

- **`dns_servers`**: Array of DNS servers for resolving real identity.getpostman.com IP (defaults to Google and Cloudflare DNS)
- **`ssl_cert`**: Custom SSL certificate path (defaults to auto-generated `ssl/cert.pem`)
- **`ssl_key`**: Custom private key path (defaults to auto-generated `ssl/key.pem`)

### Certificate Management

**Automatic Generation:**
- SSL certificates are auto-generated on first startup if missing
- Includes Subject Alternative Names: `identity.getpostman.com`, `localhost`, `127.0.0.1`
- 365-day validity period with automatic renewal when <30 days remain
- Uses OpenSSL on macOS with proper certificate configuration

**System Trust Installation:**
- Certificates are automatically added to macOS System Keychain
- Trust scope limited to SSL/TLS only (not code signing)
- Re-installed on each startup to ensure trust persistence
- Completely removed during uninstall

### Health Monitoring

**Built-in Health Endpoint:**
```bash
curl -k -H "Host: identity.getpostman.com" https://127.0.0.1/health
```

**Automatic Monitoring:**
- Hosts file integrity checking every 30 seconds
- Automatic restoration if hosts entry is removed
- Process crash detection with service restart
- Certificate expiration monitoring

### Parameter Validation

The daemon validates configuration on startup:
- Missing `postman_team_name` causes startup failure
- Invalid SAML URLs are logged but don't prevent startup
- Invalid DNS servers fall back to defaults
- Missing certificate files trigger auto-generation

## Logging and Monitoring

### Log Locations

```bash
# Service output logs
sudo tail -f /var/log/postman-saml-enforcer.log

# Service error logs  
sudo tail -f /var/log/postman-saml-enforcer-error.log

# System logs (macOS 10.12+)
sudo log show --last 1h --predicate 'process == "postman-saml-enforcer"'

# Real-time system logs
sudo log stream --predicate 'process == "postman-saml-enforcer"'
```

### Health Monitoring

The service includes automatic health monitoring:
- Process crash detection and restart
- Port availability monitoring  
- Certificate and hosts file integrity checking
- Automatic recovery from configuration drift

Test daemon health manually:
```bash
curl -k -H "Host: identity.getpostman.com" https://127.0.0.1/health
```

## Troubleshooting

### Common Issues

**Service won't start:**
```bash
# Check if port 443 is in use
sudo lsof -i :443

# Check system logs for errors
sudo log show --last 1h --predicate 'process == "postman-saml-enforcer"' --info

# Test manual startup
sudo /usr/local/postman-saml-enforcer/src/saml_enforcer.py
```

**Certificate issues:**
```bash
# Check certificate trust
security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain

# Manual certificate cleanup
sudo security delete-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain
```

**Hosts file issues:**
```bash
# Check hosts file entry
grep "identity.getpostman.com" /etc/hosts

# Manual hosts cleanup
sudo sed -i.bak '/127\.0\.0\.1.*identity\.getpostman\.com/d' /etc/hosts
```

**Process conflicts:**
```bash
# Find running daemon processes
pgrep -f saml_enforcer

# Stop all daemon processes
sudo pkill -f saml_enforcer
```

### Diagnostic Information

**Service Status:**
```bash
# Detailed service information
sudo launchctl print system/com.postman.saml-enforcer

# Service load status
sudo launchctl list com.postman.saml-enforcer
```

**Network Verification:**
```bash
# Verify DNS resolution
nslookup identity.getpostman.com 8.8.8.8

# Test connectivity to real server
curl -I https://identity.getpostman.com/login

# Verify local interception
curl -k -I -H "Host: identity.getpostman.com" https://127.0.0.1/login
```

## Security Considerations

**Privileges Required:**
- Root access for port 443 binding
- System keychain modification for certificate trust
- /etc/hosts modification for DNS redirection

**Security Measures:**
- SSL certificates use localhost + identity.getpostman.com SAN
- Certificate trust limited to SSL/TLS scope only
- Process monitoring prevents unauthorized termination
- Localhost binding only (127.0.0.1) - no external access
- Automatic cleanup on service removal

**Certificate Management:**
- Self-signed certificates auto-generated and auto-renewed (365-day validity)
- Automatic renewal 30 days before expiration
- Automatically trusted in System Keychain on each startup
- SSL-only trust scope (not code signing)
- Removed during uninstall

## Enterprise Deployment

**For MDM/Jamf Pro deployment:**
1. Package installation directory and service files
2. Deploy via policy or Self Service
3. Use Jamf's privilege escalation for sudo requirements
4. Monitor service status via extension attributes

**Configuration Profile Options:**
- Trust certificate via configuration profile
- Firewall rules for port 443 (if needed)
- Logging configuration

**Monitoring Integration:**
- Service logs accessible to standard log aggregation
- LaunchDaemon status queryable via standard tools
- Health endpoint available for external monitoring