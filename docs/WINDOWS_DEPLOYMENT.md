# Windows Deployment Guide for Postman Auth Router

## Overview

This guide provides comprehensive instructions for deploying the Postman SAML Authentication Router on Windows endpoints using Microsoft Intune, SCCM, or standalone PowerShell scripts.

### Enterprise Deployment Script Features (v1.0)

The deployment scripts include enterprise-grade enhancements:

**Security & Compliance:**
- Input parameter validation with regex patterns
- Integration with MDM certificate profiles (preferred over self-signed)
- Secure password handling via SCCM/Intune variables
- No hardcoded credentials or sensitive data

**Reliability & Resilience:**
- Retry logic with exponential backoff for network operations
- NSSM (Non-Sucking Service Manager) for robust Windows service management
- Automatic service restart on failure
- Comprehensive error handling with detailed logging

**Enterprise Integration:**
- SCCM CCM log format support
- Windows Event Log integration capability
- Support for certificate deployment profiles
- Registry-based detection methods

**Best Practices:**
- Separate detection script for Intune (2025 recommendation)
- PowerShell strict mode with `$ErrorActionPreference = 'Stop'`
- Silent progress bars for cleaner logging
- ISO-8601 date formats for log consistency

## Prerequisites

### System Requirements
- **Windows 10** version 1809 or later (Windows 11 supported)
- **Python 3.8+** installed and in PATH
- **PowerShell 5.1+** (included in Windows 10)
- **Administrator privileges** for installation

### Optional Components
- **OpenSSL** for better certificate generation (recommended)
- **Windows Terminal** for better PowerShell experience

## Local Testing & Development

### Quick Setup (Standalone)

1. **Open PowerShell as Administrator**
   ```powershell
   # Right-click PowerShell → Run as Administrator
   ```

2. **Set Execution Policy** (if needed)
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Configure and Run**
   ```powershell
   # Navigate to project directory
   cd C:\path\to\postman_redirect_daemon
   
   # Configure your IdP
   Copy-Item config\config.json.template config\config.json
   notepad config\config.json
   
   # Run setup
   .\scripts\daemon_manager.ps1 setup
   ```

### Testing the Deployment

After setup completes:

1. **Run Preflight Checks**
   ```powershell
   .\scripts\daemon_manager.ps1 preflight
   ```

2. **Test Authentication**
   - Browser: Navigate to https://postman.co
   - Desktop: Open Postman Desktop application
   - Should redirect to your SAML IdP

3. **Monitor Logs**
   ```powershell
   .\scripts\daemon_manager.ps1 logs
   ```

## Enterprise Deployment

### Method 1: Microsoft Intune

#### Package Preparation

1. **Create deployment package** with the following structure:
   ```
   PostmanAuthRouter.zip
   ├── scripts/daemon_manager.ps1
   ├── tools/
   │   └── deploy_intune.ps1
   ├── src/
   │   └── auth_router_final.py
   ├── ssl/
   │   └── cert.conf
   └── config/
       └── config.json.template
   ```

2. **Upload to Azure Storage** or internal file share

#### Intune Configuration

1. **Navigate to**: Intune > Devices > Scripts > Add > Windows 10

2. **Script Settings**:
   - Name: `Postman Auth Router Deployment`
   - Description: `Enforces SAML authentication for Postman`
   - Script: Upload `deploy_intune.ps1`

3. **Script Parameters**:
   ```powershell
   -PostmanTeamName "your-team-name"
   -OktaTenantId "your-tenant-id"
   -IdpUrl "https://your-idp.okta.com/app/..."
   -OktaAppId "your-app-id"
   ```

4. **Configuration**:
   - Run this script using the logged on credentials: **No**
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes**

5. **Assignments**:
   - Assign to appropriate device groups
   - Schedule: As soon as possible

#### Detection Script (Intune 2025 Best Practice)

As per Microsoft's latest recommendations, use the dedicated detection script for compliance monitoring:

**File**: `tools/deploy_intune_detection.ps1`

> **Important**: Intune 2025 best practices recommend using separate detection scripts rather than embedding detection logic in deployment scripts. This improves reliability and debugging.

1. **Upload to Intune**:
   - Navigate to: Devices > Scripts > Add > Windows 10
   - Script file: Upload `deploy_intune_detection.ps1`
   - Run this script using the logged on credentials: **No**
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes**

2. **Detection Features**:
   - Validates daemon installation at `$env:ProgramData\Postman\AuthRouter`
   - Checks scheduled task or NSSM service status
   - Verifies hosts file configuration
   - Confirms SSL certificate in Trusted Root store
   - Tests configuration file validity (checks for default values)
   - Optional health endpoint validation (non-blocking)

3. **Compliance Reporting**:
   - Exit 0: Compliant (properly installed and configured)
   - Exit 1: Non-compliant (detailed reasons logged for troubleshooting)

### Method 2: SCCM (Configuration Manager)

#### Application Creation

1. **Create Application** in Configuration Manager Console
   - Name: `Postman Auth Router`
   - Publisher: `Your Organization`
   - Version: `1.0.0`

2. **Deployment Type**:
   - Type: Script Installer
   - Name: `Postman Auth Router - Script`

3. **Content**:
   - Content location: `\\server\share\PostmanAuthRouter\`
   - Installation program: 
     ```
     powershell.exe -ExecutionPolicy Bypass -File deploy_sccm.ps1 -Mode Install
     ```
   - Uninstall program:
     ```
     powershell.exe -ExecutionPolicy Bypass -File deploy_sccm.ps1 -Mode Uninstall
     ```

4. **Detection Method**:
   - Type: Registry
   - Hive: HKEY_LOCAL_MACHINE
   - Key: SOFTWARE\Postman\AuthRouter
   - Value: Version
   - Data Type: String
   - Equals: 1.0.0

5. **User Experience**:
   - Installation behavior: Install for system
   - Logon requirement: Whether or not a user is logged on
   - Installation program visibility: Hidden
   - Maximum allowed run time: 30 minutes
   - Estimated installation time: 5 minutes

6. **Requirements** (optional):
   - OS: Windows 10 1809 or later
   - Free disk space: 100 MB

7. **Return Codes**:
   - 0: Success
   - 3010: Soft reboot required
   - 1603: Fatal error during installation
   - 1: Detection failed

#### Deployment

1. **Distribute Content** to distribution points
2. **Deploy** to device collections
3. **Monitor** via Deployment Monitoring

### Method 3: Group Policy with Scheduled Task

For organizations using Active Directory:

1. **Create PowerShell script** on network share:
   ```
   \\domain\sysvol\domain\scripts\PostmanAuth\install.ps1
   ```

2. **Create GPO** with Scheduled Task:
   - Action: Start a program
   - Program: `powershell.exe`
   - Arguments: `-ExecutionPolicy Bypass -File \\domain\sysvol\domain\scripts\PostmanAuth\install.ps1`
   - Run with highest privileges: Yes
   - Run whether user is logged on or not: Yes
   - Trigger: At startup

## Enterprise Certificate Management

### Using Enterprise CA Certificates

Instead of self-signed certificates, use your enterprise Certificate Authority:

1. **Generate Certificate Request**:
   ```powershell
   # Create CSR with required SANs
   $csr = @"
   [req]
   distinguished_name = req_distinguished_name
   req_extensions = v3_req
   
   [req_distinguished_name]
   CN = identity.getpostman.com
   
   [v3_req]
   subjectAltName = @alt_names
   
   [alt_names]
   DNS.1 = identity.getpostman.com
   DNS.2 = identity.postman.com
   DNS.3 = identity.postman.co
   DNS.4 = localhost
   "@
   
   $csr | Out-File -FilePath "postman-auth.csr.conf"
   openssl req -new -out postman-auth.csr -keyout postman-auth.key -config postman-auth.csr.conf
   ```

2. **Submit to Enterprise CA**:
   - Use your organization's certificate request process
   - Request a Web Server certificate
   - Include all required SANs

3. **Deploy via Intune/SCCM**:
   - Convert to PFX format if needed
   - Deploy to LocalMachine\Root store
   - Update deployment scripts to use enterprise certificate

### Certificate Deployment via Intune

1. **Create Certificate Profile**:
   - Navigate to: Devices > Configuration profiles > Create profile
   - Platform: Windows 10 and later
   - Profile type: Templates > Trusted certificate

2. **Configure Certificate**:
   - Upload your enterprise .cer file
   - Destination store: Computer certificate store - Root

3. **Assign** to same device groups as auth router

## Troubleshooting

### Common Issues

#### Python Not Found
```powershell
# Check Python installation
python --version

# If not found, install from Microsoft Store or python.org
winget install Python.Python.3.11
```

#### Certificate Trust Issues
```powershell
# Manually trust certificate
certutil -addstore -f Root "C:\ProgramData\Postman\AuthRouter\ssl\cert.pem"

# Verify certificate
certutil -store Root | findstr "identity.getpostman.com"
```

#### Port 443 Already in Use

**Important**: The daemon MUST listen on port 443 for HTTPS interception to work. Browsers always connect to port 443 for HTTPS URLs, and the hosts file can only redirect domains to IP addresses, not specific ports.

```powershell
# Find process using port 443
netstat -ano | findstr :443

# Identify the process
tasklist /FI "PID eq <PID>"
```

**Common Port 443 Conflicts:**
- **IIS (World Wide Web Publishing Service)**: Stop with `net stop W3SVC`
- **Skype for Business**: Change Skype settings to not use ports 80/443
- **VMware Workstation**: Disable VMware Host Agent service
- **Docker Desktop**: May use port 443 for certain configurations
- **Other local development servers**: Apache, nginx, Node.js apps

**Resolution Options:**

### Option 1: Stop Conflicting Service (If Not Critical)
```powershell
# Stop IIS
net stop W3SVC
iisreset /stop

# Disable IIS from starting automatically
sc config W3SVC start=disabled
```

### Option 2: Configure Reverse Proxy (Recommended for Servers)

If you need to keep the existing service on port 443, configure it to proxy Postman authentication traffic to the daemon on another available port.

**Choose any available port** for your daemon (e.g., 8443, 9443, 10443, or any unused port). The examples below use 8443, but replace with your chosen port.

#### **For IIS (using URL Rewrite and ARR)**:

1. Install Application Request Routing (ARR) and URL Rewrite modules
2. Configure the daemon to listen on your chosen port:
   ```powershell
   # In config.json, set to any available port:
   "daemon_port": 8443  # Or 9443, 10443, etc.
   ```

3. Add IIS rewrite rules in web.config (update port to match):
   ```xml
   <system.webServer>
     <rewrite>
       <rules>
         <rule name="Postman Auth Proxy" stopProcessing="true">
           <match url=".*" />
           <conditions>
             <add input="{HTTP_HOST}" pattern="^(identity\.getpostman\.com|identity\.postman\.co)$" />
           </conditions>
           <action type="Rewrite" url="https://127.0.0.1:8443/{R:0}" />
           <!-- Update port 8443 to your chosen port -->
         </rule>
       </rules>
     </rewrite>
   </system.webServer>
   ```

#### **For Apache**:
```apache
# In httpd.conf or virtual host config
<VirtualHost *:443>
    # Proxy Postman auth domains to daemon on your chosen port
    ProxyPreserveHost On
    ProxyPass / https://127.0.0.1:8443/  # Update to your port
    ProxyPassReverse / https://127.0.0.1:8443/  # Update to your port
    ServerName identity.getpostman.com
    ServerAlias identity.postman.co
</VirtualHost>
```

#### **For nginx**:
```nginx
server {
    listen 443 ssl;
    server_name identity.getpostman.com identity.postman.co;
    
    location / {
        proxy_pass https://127.0.0.1:8443;  # Update to your port
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Option 3: Windows Port Proxy (netsh)

Use Windows built-in port forwarding for specific IPs:

```powershell
# Configure daemon to listen on any available port (e.g., 8443, 9443, etc.)
# Then add port forwarding rule for localhost connections
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=443 connectaddress=127.0.0.1 connectport=8443
# Replace 8443 with your chosen port

# View current rules
netsh interface portproxy show all

# Remove when no longer needed
netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=443
```

**Note**: This requires the Windows IP Helper service and may need firewall adjustments.

### Option 4: SNI-Based Routing

For advanced deployments, use an SNI (Server Name Indication) proxy that can route based on the TLS hostname:

1. **HAProxy** example:
   ```
   frontend https_front
       bind *:443 ssl crt /path/to/cert.pem
       
       # Route based on SNI
       use_backend postman_auth if { ssl_fc_sni -i identity.getpostman.com }
       use_backend postman_auth if { ssl_fc_sni -i identity.postman.co }
       default_backend original_service
   
   backend postman_auth
       server daemon 127.0.0.1:9443 ssl verify none  # Use any available port
   
   backend original_service
       server original 127.0.0.1:8080  # Your existing service
   ```

2. **Caddy** (automatic HTTPS):
   ```
   identity.getpostman.com {
       reverse_proxy https://127.0.0.1:10443  # Use any available port
   }
   ```

**Important Considerations**:
- The daemon can listen on **any available port** (8443, 9443, 10443, etc.) when properly proxied
- Update the daemon's `config.json` to use your chosen port:
  ```json
  "advanced": {
      "daemon_port": 9443  // Your chosen port
  }
  ```
- Ensure SSL certificates are properly configured on both the proxy and daemon
- Test thoroughly to ensure authentication flow works correctly
- Consider using ports above 1024 to avoid privilege requirements on some systems

#### Daemon Won't Start
```powershell
# Check Windows Firewall
Get-NetFirewallRule -DisplayName "*Postman*"

# Check Event Viewer
Get-EventLog -LogName Application -Source "PostmanAuthRouter" -Newest 10
```

### Log Locations

- **Daemon logs**: `C:\ProgramData\Postman\logs\postman-auth.log`
- **Deployment logs**: `C:\ProgramData\Postman\logs\deployment.log`
- **SCCM logs**: `C:\Windows\CCM\Logs\AppEnforce.log`
- **Intune logs**: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\`

### Validation Commands

```powershell
# Full system check
.\scripts\daemon_manager.ps1 preflight

# Manual health check
Invoke-WebRequest -Uri "https://identity.getpostman.com/health" -UseBasicParsing

# Check all components
Get-ScheduledTask -TaskName "PostmanAuthRouter"
Get-Content C:\Windows\System32\drivers\etc\hosts | Select-String "postman"
Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -match "postman"}
```

## Rollback & Uninstall Procedures

### Method 1: Automated Uninstall (Recommended)

#### Via SCCM
```powershell
# Deploy with Uninstall mode
.\deploy_sccm.ps1 -Mode Uninstall
```

The SCCM uninstall process will:
1. Stop and remove NSSM service or scheduled task
2. Remove hosts file entries (using safe markers)
3. Remove certificates from Trusted Root store
4. Delete installation directory
5. Remove registry entries
6. Clear firewall rules
7. Flush DNS cache

#### Via Intune Remediation Script
Create a remediation script in Intune to remove the deployment:
```powershell
# Intune Remediation Script for removal
$serviceName = "PostmanAuthRouter"

# Stop service/task
Stop-ScheduledTask -TaskName $serviceName -ErrorAction SilentlyContinue
Get-Service -Name $serviceName -ErrorAction SilentlyContinue | Stop-Service -Force

# Unregister scheduled task
Unregister-ScheduledTask -TaskName $serviceName -Confirm:$false -ErrorAction SilentlyContinue

# Remove NSSM service if exists
if (Test-Path "$env:ProgramData\Postman\AuthRouter\nssm.exe") {
    & "$env:ProgramData\Postman\AuthRouter\nssm.exe" remove $serviceName confirm
}

# Clean hosts file (safe removal using markers)
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$content = Get-Content $hostsFile -Raw
$pattern = "(?ms)# BEGIN POSTMAN-AUTH-ROUTER.*?# END POSTMAN-AUTH-ROUTER\r?\n?"
$newContent = $content -replace $pattern, ""
Set-Content -Path $hostsFile -Value $newContent -NoNewline

# Remove certificates
Get-ChildItem -Path Cert:\LocalMachine\Root | 
    Where-Object { $_.Subject -match "identity.getpostman.com" } | 
    Remove-Item -Force

# Remove firewall rules
Remove-NetFirewallRule -DisplayName "*Postman Auth Router*" -ErrorAction SilentlyContinue

# Remove installation directory
Remove-Item -Path "$env:ProgramData\Postman\AuthRouter" -Recurse -Force -ErrorAction SilentlyContinue

# Clear registry
Remove-Item -Path "HKLM:\SOFTWARE\Postman\AuthRouter" -Recurse -Force -ErrorAction SilentlyContinue

# Flush DNS
ipconfig /flushdns

Write-Output "Postman Auth Router removed successfully"
exit 0
```

### Method 2: Manual Cleanup

```powershell
# Run standalone cleanup script
.\scripts\daemon_manager.ps1 cleanup

# Or manual steps if needed:
Stop-ScheduledTask -TaskName "PostmanAuthRouter"
Unregister-ScheduledTask -TaskName "PostmanAuthRouter" -Confirm:$false
Remove-NetFirewallRule -DisplayName "*Postman Auth Router*"
# Edit hosts file to remove entries between markers
notepad C:\Windows\System32\drivers\etc\hosts
# Remove certificates
Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -match "postman"} | Remove-Item
# Remove installation folder
Remove-Item -Path "C:\ProgramData\Postman" -Recurse -Force
```

### Help Desk Remote Execution

For help desk teams to remotely uninstall via ConfigMgr or Intune:

1. **ConfigMgr Remote Control**:
   ```powershell
   # Connect to device and run
   Invoke-Command -ComputerName <DeviceName> -ScriptBlock {
       & "C:\Path\To\deploy_sccm.ps1" -Mode Uninstall
   }
   ```

2. **Intune Device Action**:
   - Deploy uninstall script as Win32 app with uninstall command
   - Use Intune remediation scripts for targeted removal
   - Monitor compliance via detection script

## Security Considerations

### Best Practices

1. **Use Enterprise Certificates** instead of self-signed
2. **Deploy via MDM** to prevent user tampering
3. **Monitor logs** centrally via SIEM
4. **Restrict PowerShell execution** to signed scripts only
5. **Use AppLocker** to prevent unauthorized modifications

### Compliance

- Logs all authentication attempts
- Supports audit requirements
- No data leaves the device
- Compatible with BitLocker and Windows Defender

## Support

For issues specific to Windows deployment:
1. Check this guide's troubleshooting section
2. Review logs in `C:\ProgramData\Postman\logs\`
3. Verify all prerequisites are met
4. Test with `.\scripts\daemon_manager.ps1 preflight`

---

*Last updated: 2025-08-17*