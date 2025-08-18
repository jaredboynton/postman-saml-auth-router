# Deployment Guide

## Prerequisites

### System Requirements
- **macOS**: 10.15+ (Catalina or newer)
- **Windows**: Windows 10+ or Server 2019+
- **Linux**: Ubuntu 20.04+, RHEL 8+, or equivalent
- **Python**: 3.8 or higher
- **Privileges**: Administrative/root access required

### Enterprise Requirements
- SAML 2.0 compatible IdP (Okta, Azure AD, Ping Identity, OneLogin)
- MDM solution for fleet deployment (JAMF, Intune, SCCM, Workspace ONE)
- Postman Enterprise team with SAML configured
- Enterprise CA for production certificates (recommended)

## Quick Start Deployment

### macOS / Linux

```bash
# 1. Clone or download the repository
git clone <repository-url>
cd postman_redirect_daemon

# 2. Configure your IdP settings
cp config/config.json.template config/config.json
vi config/config.json  # Add your team name and IdP details

# 3. Run complete setup
sudo ./scripts/daemon_manager.sh setup

# 4. Verify deployment
sudo ./scripts/daemon_manager.sh status
curl -k https://localhost:443/health
```

### Windows

```powershell
# 1. Clone or download the repository
git clone <repository-url>
cd postman_redirect_daemon

# 2. Configure your IdP settings (Run as Administrator)
Copy-Item config\config.json.template config\config.json
notepad config\config.json  # Add your team name and IdP details

# 3. Run complete setup (PowerShell as Administrator)
.\scripts\daemon_manager.ps1 setup

# 4. Verify deployment
.\scripts\daemon_manager.ps1 status
Invoke-WebRequest -Uri https://localhost:443/health -SkipCertificateCheck
```

## Enterprise MDM Deployment

### JAMF (macOS)

#### Package Creation
```bash
# Create deployment package
./tools/create_jamf_package.sh \
  --team "your-team-name" \
  --idp-type "okta" \
  --tenant-id "your-tenant-id"

# Output: PostmanAuthRouter.pkg
```

#### JAMF Policy Configuration
1. Upload `PostmanAuthRouter.pkg` to JAMF Admin
2. Create Smart Computer Group for target devices
3. Create Policy with:
   - Trigger: `enrollment`, `recurring check-in`
   - Frequency: Once per computer
   - Package: `PostmanAuthRouter.pkg`
   - Scripts: Post-install verification script

#### JAMF Extension Attribute
```bash
#!/bin/bash
# Check daemon status
if pgrep -f "auth_router_final.py" > /dev/null; then
    echo "<result>Running</result>"
else
    echo "<result>Not Running</result>"
fi
```

### Intune (Windows)

#### PowerShell Deployment Script
```powershell
# Save as: Deploy-PostmanAuth.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$PostmanTeamName,
    
    [Parameter(Mandatory=$true)]
    [string]$IdpType,
    
    [Parameter(Mandatory=$true)]
    [string]$TenantId
)

# Download and extract package
$tempPath = "$env:TEMP\postman-auth"
Invoke-WebRequest -Uri "https://your-cdn/postman-auth.zip" -OutFile "$tempPath.zip"
Expand-Archive -Path "$tempPath.zip" -DestinationPath $tempPath

# Configure
$config = @{
    postman_team_name = $PostmanTeamName
    idp_config = @{
        idp_type = $IdpType
        tenant_id = $TenantId
    }
} | ConvertTo-Json

Set-Content -Path "$tempPath\config\config.json" -Value $config

# Install
& "$tempPath\scripts\daemon_manager.ps1" setup

# Verify
$health = Invoke-RestMethod -Uri "https://localhost:443/health" -SkipCertificateCheck
if ($health.status -eq "healthy") {
    Write-Output "Deployment successful"
    exit 0
} else {
    Write-Error "Deployment failed"
    exit 1
}
```

#### Intune Configuration
1. Navigate to **Devices > Scripts > Add > Windows 10**
2. Upload `Deploy-PostmanAuth.ps1`
3. Settings:
   - Run this script using the logged on credentials: **No**
   - Enforce script signature check: **No**
   - Run script in 64 bit PowerShell Host: **Yes**
4. Assign to device groups

### SCCM (Windows)

#### Application Model Deployment
```powershell
# Detection Method Script
if (Get-Service -Name "PostmanAuthDaemon" -ErrorAction SilentlyContinue) {
    if ((Get-Service "PostmanAuthDaemon").Status -eq "Running") {
        Write-Output "Installed"
        exit 0
    }
}
exit 1
```

#### Installation Program
```powershell
# Install.ps1
.\scripts\daemon_manager.ps1 setup -Silent
```

#### Uninstallation Program
```powershell
# Uninstall.ps1
.\scripts\daemon_manager.ps1 cleanup -Silent
```

### Workspace ONE (Cross-Platform)

#### macOS Profile
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.postman.auth.daemon</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.company.postman.auth</string>
            <key>Config</key>
            <dict>
                <key>TeamName</key>
                <string>your-team</string>
                <key>IdpType</key>
                <string>okta</string>
                <key>TenantId</key>
                <string>your-tenant</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>
```

## Certificate Management

### Using Enterprise Certificates

#### Generate CSR
```bash
# Generate private key and CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout ssl/key.pem \
  -out ssl/cert.csr \
  -config ssl/cert.conf \
  -subj "/CN=identity.getpostman.com/O=Your Company/C=US"
```

#### Submit to Enterprise CA
1. Submit CSR to your enterprise CA (Microsoft ADCS, Venafi, DigiCert)
2. Request certificate with:
   - Template: Web Server or SSL Certificate
   - SAN entries: All Postman domains (see cert.conf)
3. Download certificate chain

#### Deploy Certificate
```bash
# Place certificates
cp enterprise-cert.pem ssl/cert.pem
cp enterprise-key.pem ssl/key.pem
cp enterprise-chain.pem ssl/chain.pem

# Restart daemon
sudo ./scripts/daemon_manager.sh restart
```

### MDM Certificate Deployment

#### JAMF Certificate Profile
1. Create Configuration Profile
2. Add Certificate payload
3. Upload enterprise certificate
4. Scope to computer groups

#### Intune Certificate Profile
1. Create Device Configuration Profile
2. Platform: Windows 10 and later
3. Profile type: Trusted certificate
4. Upload root and intermediate certificates

## Production Configuration

### High Availability Setup

#### Primary/Backup Configuration
```json
{
  "postman_team_name": "production-team",
  "idp_config": {
    "idp_type": "okta",
    "okta_tenant_id": "prod-tenant",
    "backup_idp_url": "https://backup.okta.com/app/..."
  },
  "advanced": {
    "health_check_interval": 60,
    "auto_restart_on_failure": true,
    "max_restart_attempts": 3
  }
}
```

#### Load Distribution
For large deployments (>10,000 devices):
- Use regional configuration files
- Stagger deployment windows
- Monitor resource usage via MDM

### Monitoring Integration

#### Splunk Forwarder
```bash
# /etc/splunk/system/local/inputs.conf
[monitor:///var/log/postman-auth.log]
disabled = false
index = security
sourcetype = postman_auth
```

#### Elastic/ELK Stack
```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/postman-auth.log
  fields:
    service: postman-auth
    environment: production
```

#### Datadog
```yaml
# /etc/datadog-agent/conf.d/postman_auth.yaml
logs:
  - type: file
    path: /var/log/postman-auth.log
    service: postman-auth
    source: python
    tags:
      - env:production
      - team:security
```

## Session Management Deployment

### Automated Session Clearing

#### Deploy via JAMF
```bash
#!/bin/bash
# JAMF script to clear all Postman sessions
/usr/local/bin/postman/tools/clear_mac_sessions.sh

# Report status
if [ $? -eq 0 ]; then
    echo "Sessions cleared successfully"
    jamf recon
else
    echo "Failed to clear sessions"
    exit 1
fi
```

#### Deploy via Intune
```powershell
# Intune remediation script
try {
    & "C:\ProgramData\Postman\tools\clear_win_sessions.ps1"
    Write-Output "Sessions cleared"
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
```

## Rollback Procedures

### Emergency Rollback

#### macOS/Linux
```bash
# Stop daemon
sudo ./scripts/daemon_manager.sh stop

# Remove hosts entries
sudo ./scripts/daemon_manager.sh cleanup

# Remove certificates
sudo security delete-certificate -c "identity.getpostman.com" \
  /Library/Keychains/System.keychain

# Uninstall
sudo rm -rf /usr/local/bin/postman
```

#### Windows
```powershell
# Stop service
Stop-Service PostmanAuthDaemon -Force

# Remove hosts entries
.\scripts\daemon_manager.ps1 cleanup

# Remove certificates
Get-ChildItem Cert:\LocalMachine\Root | 
  Where-Object {$_.Subject -like "*postman*"} | 
  Remove-Item

# Uninstall
Remove-Item -Path "C:\ProgramData\Postman" -Recurse -Force
```

### Gradual Rollback
1. Remove from test group first
2. Monitor for 24 hours
3. Remove from pilot group
4. Monitor for 48 hours
5. Remove from production if issues persist

## Troubleshooting Deployment

### Common Deployment Issues

#### "Port 443 already in use"
```bash
# Find process using port 443
sudo lsof -i :443  # macOS/Linux
netstat -ano | findstr :443  # Windows

# Kill process or change daemon port
```

#### "Certificate not trusted"
```bash
# Regenerate and trust certificate
sudo ./scripts/daemon_manager.sh generate-cert
sudo ./scripts/daemon_manager.sh trust-cert
```

#### "Hosts file not updating"
```bash
# Check permissions
ls -la /etc/hosts  # Should be writable by root

# Manually add entries if needed
sudo echo "127.0.0.1 identity.getpostman.com" >> /etc/hosts
```

### Validation Checklist

Post-deployment validation:
- [ ] Daemon running (`ps aux | grep auth_router`)
- [ ] Port 443 listening (`netstat -an | grep 443`)
- [ ] Hosts file updated (`grep postman /etc/hosts`)
- [ ] Certificate trusted (browse to https://localhost:443/health)
- [ ] Health endpoint responding
- [ ] Authentication redirects to IdP
- [ ] Sessions persist after authentication
- [ ] Logs being generated

## Maintenance Procedures

### Certificate Renewal
```bash
# 30 days before expiration
./scripts/daemon_manager.sh generate-cert
./scripts/daemon_manager.sh trust-cert
./scripts/daemon_manager.sh restart
```

### Configuration Updates
```bash
# Update config
vi config/config.json

# Reload without restart
sudo kill -HUP $(pgrep -f auth_router_final.py)
```

### Log Rotation
```bash
# Force rotate logs
sudo logrotate -f /etc/logrotate.d/postman-auth

# Archive old logs
tar -czf postman-logs-$(date +%Y%m%d).tar.gz /var/log/postman-auth.*.gz
```