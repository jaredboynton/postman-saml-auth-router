# Windows Service Deployment Guide

Postman SAML Enforcer - Windows Service Installation

## Overview

This directory contains the automated installation system for deploying the Postman SAML Enforcer as a persistent Windows system service.

The service automatically:
- Starts on system boot
- Restarts on crashes with configurable recovery
- Runs with Administrator privileges
- Manages SSL certificates and system trust
- Maintains hosts file entries
- Integrates with Windows Event Log

## Quick Start

```powershell
# Run PowerShell as Administrator

# Install and start service
.\service\windows\install-service.ps1 install

# Check service status
.\service\windows\install-service.ps1 status

# Stop service
.\service\windows\install-service.ps1 stop

# Clear all Postman sessions (browsers & applications)
.\service\windows\install-service.ps1 srefresh

# Complete removal (service, certificates, hosts entries, logs)
.\service\windows\install-service.ps1 uninstall
```

## Prerequisites

**Required Privileges:**
- Administrator access (run PowerShell as Administrator)
- Port 443 binding capability
- Local Machine certificate store modification rights

**Dependencies:**
- Python 3.12+ (automatically installed if missing)
- pywin32 package (automatically installed with Python)
- PowerShell 5.0+ (included with Windows 10/11)

## Installation Options

### Production Installation

Installs as persistent Windows service with automatic startup:

```powershell
.\service\windows\install-service.ps1 install
```

**What this does:**
1. Detects and installs Python 3.12 if missing (via winget or direct download)
2. Installs pywin32 package if needed
3. Copies application to `C:\Program Files\Postman SAML Enforcer`
4. Creates Windows service "PostmanSAMLEnforcer"
5. Configures automatic restart on failure
6. Starts service immediately
7. Service starts automatically on boot

### Test Mode

Runs daemon directly without service installation:

```powershell
.\service\windows\install-service.ps1 start
```

If no service is installed, automatically starts in test mode:
- Runs daemon process directly in background
- Good for testing and development
- Must stop manually (does not auto-restart)
- Shows process information for monitoring

## Service Management

### Status Check

```powershell
.\service\windows\install-service.ps1 status
```

Shows:
- Windows service status and configuration
- Running process information (PID)
- Test daemon processes (if any)
- Service startup type and recovery settings

### Start/Stop Service

```powershell
# Start service (or test mode if not installed)
.\service\windows\install-service.ps1 start

# Stop service and any test daemons
.\service\windows\install-service.ps1 stop
```

### Advanced Windows Service Commands

```powershell
# Check Windows service status
Get-Service PostmanSAMLEnforcer

# Service control via Service Control Manager
Start-Service PostmanSAMLEnforcer
Stop-Service PostmanSAMLEnforcer
Restart-Service PostmanSAMLEnforcer

# View service configuration
Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq "PostmanSAMLEnforcer"}
```

## Session Management

### Clear Postman Sessions

The `srefresh` command provides comprehensive session clearing to ensure fresh SAML authentication:

```powershell
.\service\windows\install-service.ps1 srefresh
```

**What this does:**
1. **Detects Running Applications:** Uses `tasklist` to find Postman.exe and PostmanEnterprise.exe processes
2. **Graceful Application Shutdown:** Uses `taskkill` to terminate processes
3. **Browser Cookie Clearing:**
   - **Chrome:** Direct SQLite database manipulation in User Data directories
   - **Firefox:** Process termination, cookie database cleaning, auto-restart
   - **Brave:** Chromium-based cookie database cleaning
   - **Edge:** Similar Chromium-based approach for cookie clearing
4. **Application Session Files:** Removes `userPartitionData.json` from `%APPDATA%` directories
5. **Process Restart:** Automatically restarts applications using installation paths

**Windows-Specific Process Management:**
- Uses `tasklist /FO CSV` for process enumeration
- Graceful termination via `taskkill /IM <process> /F`
- Handles both standard and Enterprise Postman installations
- Searches common installation paths: `%LOCALAPPDATA%\Postman` and `%LOCALAPPDATA%\PostmanEnterprise`

**Targeted Cookie Domains:**
- Core Postman domains (.postman.com, .getpostman.com)
- Authentication domains (identity.postman.com, id.gw.postman.com)
- Legacy domains (.postman.co, god.postman.co)
- CDN and security cookies (Cloudflare, analytics)

**Business Domain Preservation:**
The session cleaner preserves business-critical cookies (Salesforce, Okta, Looker, etc.) while targeting only Postman authentication domains.

**Windows File Paths Cleared:**
- `%APPDATA%\Mozilla\Firefox\Profiles\*\cookies.sqlite`
- `%LOCALAPPDATA%\Google\Chrome\User Data\*\Cookies`
- `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\*\Cookies`
- `%APPDATA%\Postman\storage\userPartitionData.json`
- `%APPDATA%\PostmanEnterprise\storage\userPartitionData.json`

**When to use:**
- Initial deployment to ensure fresh SAML authentication
- After SAML configuration changes
- When users report cached authentication issues
- Regular maintenance to enforce authentication policies

## Complete Removal

```powershell
.\service\windows\install-service.ps1 uninstall
```

**Removes all traces:**
- Stops and removes Windows service
- Stops any running daemon processes
- Removes hosts file entries for identity.getpostman.com
- Removes trusted certificates from Local Machine Root store
- Deletes service log files
- Removes empty ProgramData directories

## Service Configuration

**Service Name:** `PostmanSAMLEnforcer`
**Display Name:** `Postman SAML Enforcer`
**Description:** `Enterprise SAML enforcement daemon for Postman Desktop applications`

**Key Features:**
- Automatic startup (Service start type: Automatic)
- Failure recovery: Restart after 5, 10, 15 seconds
- Runs in own process (Service type: Own)
- Administrator privileges
- Process health monitoring with automatic restart

**Installation Directory:** `C:\Program Files\Postman SAML Enforcer`

**Service Wrapper:** `service_wrapper.py` - Python Windows Service wrapper
- Manages daemon process lifecycle
- Monitors process health
- Handles service start/stop events
- Automatic restart on crashes (up to 5 attempts in 5 minutes)

**Network Configuration:**
- Listens on 127.0.0.1:443 (localhost only, port 443 required for browser compatibility)
- Proxies to real identity.getpostman.com

## Configuration

### Configuration File Setup

The daemon requires a configuration file at `config\config.json` in the project directory:

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
  "ssl_cert": "ssl\\cert.pem",
  "ssl_key": "ssl\\key.pem"
}
```

- **`dns_servers`**: Array of DNS servers for resolving real identity.getpostman.com IP (defaults to Google and Cloudflare DNS)
- **`ssl_cert`**: Custom SSL certificate path (defaults to auto-generated `ssl\cert.pem`)
- **`ssl_key`**: Custom private key path (defaults to auto-generated `ssl\key.pem`)

### Certificate Management

**Automatic Generation:**
- SSL certificates are auto-generated on first startup if missing
- Includes Subject Alternative Names: `identity.getpostman.com`, `localhost`, `127.0.0.1`
- 365-day validity period with automatic renewal when <30 days remain
- Uses PowerShell PKI on Windows with RSA 2048-bit encryption

**System Trust Installation:**
- Certificates are automatically added to Local Machine Trusted Root Certification Authorities
- Re-installed on each startup to ensure trust persistence
- Completely removed during uninstall

### Health Monitoring

**Built-in Health Endpoint:**
```powershell
Invoke-WebRequest -Uri "https://127.0.0.1/health" -Headers @{"Host"="identity.getpostman.com"} -SkipCertificateCheck
```

**Automatic Monitoring:**
- Hosts file integrity checking every 30 seconds
- Automatic restoration if hosts entry is removed
- Process crash detection with service restart (up to 5 attempts per 5 minutes)
- Certificate expiration monitoring

### Parameter Validation

The daemon validates configuration on startup:
- Missing `postman_team_name` causes startup failure
- Invalid SAML URLs are logged but don't prevent startup
- Invalid DNS servers fall back to defaults
- Missing certificate files trigger auto-generation

## Logging and Monitoring

### Log Locations

```powershell
# Service logs (managed by service wrapper)
Get-Content "C:\ProgramData\Postman\saml-enforcer-service.log" -Tail 50

# Windows Event Log (Application)
Get-WinEvent -LogName Application | Where-Object {$_.ProviderName -eq "PostmanSAMLEnforcer"} | Select-Object -First 10

# Real-time log monitoring
Get-Content "C:\ProgramData\Postman\saml-enforcer-service.log" -Wait
```

### Windows Event Log Integration

The service logs important events to Windows Event Log:
- Service start/stop events
- Process crashes and restarts
- Configuration errors
- Certificate and network issues

View in Event Viewer: `Applications and Services Logs`

### Health Monitoring

The service includes comprehensive health monitoring:
- Process crash detection and restart (max 5 restarts per 5 minutes)
- Port availability monitoring
- Certificate and hosts file integrity checking
- Automatic recovery from configuration drift

Test daemon health manually:
```powershell
# Test health endpoint
Invoke-WebRequest -Uri "https://127.0.0.1/health" -Headers @{"Host"="identity.getpostman.com"} -SkipCertificateCheck
```

## Automatic Python Installation

The installer automatically handles Python requirements:

**Installation Methods (in order of preference):**
1. **winget** (Windows Package Manager) - cleanest installation
2. **Direct download** - fallback if winget unavailable

**Python Version:** 3.12.0 (AMD64)
**Installation Scope:** All Users with PATH modification
**Configuration:** Includes pip, excludes test suite

**Manual Python verification:**
```powershell
# Check Python installation
python --version
Get-Command python

# Check pywin32 installation
python -c "import win32serviceutil; print('pywin32 available')"
```

## Troubleshooting

### Common Issues

**Service won't start:**
```powershell
# Check if port 443 is in use
netstat -an | Select-String "127.0.0.1:443.*LISTENING"

# Check Windows Event Log for errors
Get-WinEvent -LogName Application | Where-Object {$_.ProviderName -eq "PostmanSAMLEnforcer"} | Select-Object -First 5

# Test manual startup
python "C:\Program Files\Postman SAML Enforcer\src\saml_enforcer.py"
```

**Certificate issues:**
```powershell
# Check certificate trust
Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object {$_.Subject -like "*identity.getpostman.com*"}

# Manual certificate cleanup
$certs = Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object {$_.Subject -like "*identity.getpostman.com*"}
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$certs | ForEach-Object { $store.Remove($_) }
$store.Close()
```

**Hosts file issues:**
```powershell
# Check hosts file entry
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Select-String "identity.getpostman.com"

# Manual hosts cleanup
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$content = Get-Content $hostsFile | Where-Object {$_ -notmatch "127\.0\.0\.1.*identity\.getpostman\.com"}
$content | Set-Content $hostsFile
```

**Process conflicts:**
```powershell
# Find running daemon processes
Get-WmiObject Win32_Process | Where-Object {$_.Name -match "python" -and $_.CommandLine -like "*saml_enforcer.py*"}

# Stop all daemon processes
Get-WmiObject Win32_Process | Where-Object {$_.Name -match "python" -and $_.CommandLine -like "*saml_enforcer.py*"} | ForEach-Object {Stop-Process -Id $_.ProcessId -Force}
```

**Python installation issues:**
```powershell
# Check winget availability
winget --version

# Manual Python installation
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe" -OutFile "$env:TEMP\python-installer.exe"
& "$env:TEMP\python-installer.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
```

### Diagnostic Information

**Service Status:**
```powershell
# Detailed service information
Get-Service PostmanSAMLEnforcer | Format-List *

# Service recovery configuration
sc.exe qfailure PostmanSAMLEnforcer

# Process information
Get-WmiObject Win32_Service | Where-Object {$_.Name -eq "PostmanSAMLEnforcer"} | Select-Object ProcessId, StartMode, State
```

**Network Verification:**
```powershell
# Verify DNS resolution
nslookup identity.getpostman.com 8.8.8.8

# Test connectivity to real server
Invoke-WebRequest -Uri "https://identity.getpostman.com/login" -Method HEAD

# Verify local interception
Invoke-WebRequest -Uri "https://127.0.0.1/login" -Headers @{"Host"="identity.getpostman.com"} -SkipCertificateCheck -Method HEAD
```

## Security Considerations

**Privileges Required:**
- Administrator access for port 443 binding
- Local Machine certificate store modification
- Windows hosts file modification
- Service installation and management

**Security Measures:**
- SSL certificates use localhost + identity.getpostman.com SAN
- Certificates added to Trusted Root Certification Authorities
- Process monitoring prevents unauthorized termination
- Localhost binding only (127.0.0.1) - no external access
- Automatic cleanup on service removal

**Certificate Management:**
- Self-signed certificates auto-generated and auto-renewed (365-day validity)
- Automatic renewal 30 days before expiration
- Automatically trusted in Local Machine Root store on each startup
- RSA 2048-bit encryption with proper SAN entries
- Removed during uninstall

## Enterprise Deployment

**For SCCM/Microsoft Endpoint Manager:**
1. Package PowerShell script and dependencies
2. Deploy via Application or Package deployment
3. Use system context for Administrator privileges
4. Monitor deployment status via SCCM reports

**Group Policy Integration:**
- Service configuration via Group Policy Preferences
- Certificate deployment via Group Policy (optional)
- Firewall rules for port 443 (if needed)
- PowerShell execution policy configuration

**Microsoft Intune Deployment:**
- Deploy as Win32 app with PowerShell script
- Use system context for installation
- Configure detection rules for service status
- Monitor via Intune device compliance

**Enterprise Monitoring:**
- Windows Event Log integration for SIEM
- Service status monitoring via SCOM/System Center
- Log forwarding to enterprise log management
- Health endpoint for external monitoring tools