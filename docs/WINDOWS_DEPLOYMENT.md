# Windows Deployment Guide for Postman Auth Router

## Overview

This guide provides comprehensive instructions for deploying the Postman SAML Authentication Router on Windows endpoints using Microsoft Intune, SCCM, or standalone PowerShell scripts.

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
   .\daemon_manager.ps1 setup
   ```

### Testing the Deployment

After setup completes:

1. **Run Preflight Checks**
   ```powershell
   .\daemon_manager.ps1 preflight
   ```

2. **Test Authentication**
   - Browser: Navigate to https://postman.co
   - Desktop: Open Postman Desktop application
   - Should redirect to your SAML IdP

3. **Monitor Logs**
   ```powershell
   .\daemon_manager.ps1 logs
   ```

## Enterprise Deployment

### Method 1: Microsoft Intune

#### Package Preparation

1. **Create deployment package** with the following structure:
   ```
   PostmanAuthRouter.zip
   ├── daemon_manager.ps1
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

#### Detection Script

Create a separate detection script for compliance:

```powershell
# Save as: detect_postman_auth.ps1
$installed = $true

# Check scheduled task
$task = Get-ScheduledTask -TaskName "PostmanAuthRouter" -ErrorAction SilentlyContinue
if (-not $task -or $task.State -ne "Running") {
    $installed = $false
}

# Check hosts file
$hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts"
if ($hosts -notmatch "127.0.0.1.*identity.getpostman.com") {
    $installed = $false
}

# Check certificate
$cert = Get-ChildItem Cert:\LocalMachine\Root | 
    Where-Object { $_.Subject -match "identity.getpostman.com" }
if (-not $cert) {
    $installed = $false
}

if ($installed) {
    Write-Output "Installed"
    exit 0
} else {
    Write-Output "Not Installed"
    exit 1
}
```

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
```powershell
# Find process using port 443
netstat -ano | findstr :443

# Kill process (replace PID)
taskkill /PID <PID> /F
```

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
.\daemon_manager.ps1 preflight

# Manual health check
Invoke-WebRequest -Uri "https://identity.getpostman.com/health" -UseBasicParsing

# Check all components
Get-ScheduledTask -TaskName "PostmanAuthRouter"
Get-Content C:\Windows\System32\drivers\etc\hosts | Select-String "postman"
Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -match "postman"}
```

## Rollback Procedure

If deployment needs to be reversed:

```powershell
# Run cleanup
.\daemon_manager.ps1 cleanup

# Or via SCCM
.\deploy_sccm.ps1 -Mode Uninstall

# Manual cleanup if needed
Stop-ScheduledTask -TaskName "PostmanAuthRouter"
Unregister-ScheduledTask -TaskName "PostmanAuthRouter" -Confirm:$false
Remove-NetFirewallRule -DisplayName "*Postman Auth Router*"
# Remove hosts entries manually
notepad C:\Windows\System32\drivers\etc\hosts
```

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
4. Test with `.\daemon_manager.ps1 preflight`

---

*Last updated: 2025-08-17*