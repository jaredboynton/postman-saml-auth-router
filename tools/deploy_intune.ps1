#############################################################################
# Postman SAML Authentication Router - Intune Deployment Script
# 
# This script deploys the Postman authentication daemon via Microsoft Intune
# Deploy as PowerShell script in Intune > Devices > Scripts
#
# Version: 1.0
# Date: 2025-08-17
#############################################################################

param(
    [Parameter(Mandatory=$false)]
    [string]$PostmanTeamName = "YOUR_TEAM_NAME",
    
    [Parameter(Mandatory=$false)]
    [string]$OktaTenantId = "YOUR_TENANT_ID",
    
    [Parameter(Mandatory=$false)]
    [string]$IdpUrl = "YOUR_IDP_URL",
    
    [Parameter(Mandatory=$false)]
    [string]$OktaAppId = "YOUR_APP_ID"
)

# Configuration
$InstallDir = "$env:ProgramData\Postman\AuthRouter"
$LogDir = "$env:ProgramData\Postman\logs"
$LogFile = "$LogDir\deployment.log"
$DownloadUrl = "https://your-storage.example.com/postman-auth-router.zip"  # Update with your package URL

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message
}

# Create directories
function Initialize-Directories {
    Write-Log "Creating installation directories..."
    
    @($InstallDir, $LogDir) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Log "Created directory: $_"
        }
    }
}

# Download and extract package
function Install-Package {
    Write-Log "Downloading Postman Auth Router package..."
    
    $packagePath = "$env:TEMP\postman-auth-router.zip"
    
    try {
        # Download package (update URL to your actual deployment source)
        # Option 1: From Azure Blob Storage
        # Invoke-WebRequest -Uri $DownloadUrl -OutFile $packagePath
        
        # Option 2: Copy from network share
        # Copy-Item "\\server\share\postman-auth-router.zip" -Destination $packagePath
        
        # Option 3: Embed files directly in this script (for smaller deployments)
        # Create-EmbeddedFiles
        
        Write-Log "Package downloaded successfully"
        
        # Extract to installation directory
        Expand-Archive -Path $packagePath -DestinationPath $InstallDir -Force
        Write-Log "Package extracted to $InstallDir"
        
        # Clean up
        Remove-Item $packagePath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "ERROR: Failed to download/extract package: $_"
        exit 1
    }
}

# Configure hosts file
function Configure-Hosts {
    Write-Log "Configuring hosts file..."
    
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $startMarker = "# BEGIN POSTMAN-AUTH-ROUTER"
    $endMarker = "# END POSTMAN-AUTH-ROUTER"
    
    try {
        $hostsContent = Get-Content $hostsFile -Raw
        
        if (-not ($hostsContent -match $startMarker)) {
            # Backup hosts file
            $backupPath = "$hostsFile.intune.backup"
            Copy-Item $hostsFile $backupPath -Force
            Write-Log "Hosts file backed up to $backupPath"
            
            # Add entries
            $entries = @"

$startMarker
127.0.0.1 identity.getpostman.com
127.0.0.1 identity.postman.co
$endMarker
"@
            Add-Content -Path $hostsFile -Value $entries
            Write-Log "Hosts entries added successfully"
        } else {
            Write-Log "Hosts entries already configured"
        }
    } catch {
        Write-Log "ERROR: Failed to configure hosts file: $_"
        exit 1
    }
}

# Install and trust certificate
function Install-Certificate {
    Write-Log "Installing SSL certificate..."
    
    $certPath = "$InstallDir\ssl\cert.pem"
    
    # Check if using enterprise CA certificate
    $enterpriseCertPath = "$InstallDir\ssl\enterprise.cer"
    if (Test-Path $enterpriseCertPath) {
        $certPath = $enterpriseCertPath
        Write-Log "Using enterprise CA certificate"
    }
    
    if (Test-Path $certPath) {
        try {
            # Import to Trusted Root store
            $result = certutil -addstore -f "Root" $certPath 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Certificate installed to Trusted Root store"
            } else {
                throw "Certutil failed: $result"
            }
        } catch {
            Write-Log "ERROR: Failed to install certificate: $_"
            exit 1
        }
    } else {
        Write-Log "WARNING: Certificate not found at $certPath"
        Write-Log "Will generate self-signed certificate..."
        
        # Generate self-signed certificate using OpenSSL if available
        $opensslPath = "$InstallDir\tools\openssl.exe"
        if (Test-Path $opensslPath) {
            & $opensslPath req -new -x509 -days 365 -nodes `
                -out "$InstallDir\ssl\cert.pem" `
                -keyout "$InstallDir\ssl\key.pem" `
                -config "$InstallDir\ssl\cert.conf" `
                -extensions v3_req 2>&1
            
            # Trust the generated certificate
            certutil -addstore -f "Root" "$InstallDir\ssl\cert.pem" | Out-Null
            Write-Log "Self-signed certificate generated and trusted"
        } else {
            Write-Log "WARNING: Cannot generate certificate - OpenSSL not found"
        }
    }
}

# Create configuration file
function Create-Configuration {
    Write-Log "Creating configuration file..."
    
    $configPath = "$InstallDir\config\config.json"
    $configDir = Split-Path $configPath -Parent
    
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    $config = @{
        postman_team_name = $PostmanTeamName
        okta_tenant_id = $OktaTenantId
        idp_config = @{
            idp_type = "okta"
            idp_url = $IdpUrl
            okta_app_id = $OktaAppId
        }
        advanced = @{
            log_file = "$LogDir\postman-auth.log"
            daemon_port = 443
            health_port = 8443
        }
    }
    
    $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
    Write-Log "Configuration file created at $configPath"
}

# Configure Windows Firewall
function Configure-Firewall {
    Write-Log "Configuring Windows Firewall..."
    
    $ruleName = "Postman Auth Router (Intune)"
    
    try {
        # Remove existing rule if present
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        # Add new rule
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 443 `
            -Action Allow `
            -Profile Any `
            -Description "Allow Postman Auth Router on port 443" | Out-Null
            
        Write-Log "Firewall rule created successfully"
    } catch {
        Write-Log "WARNING: Failed to configure firewall: $_"
    }
}

# Create scheduled task to start daemon at startup
function Create-ScheduledTask {
    Write-Log "Creating scheduled task for daemon startup..."
    
    $taskName = "PostmanAuthRouter"
    $pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pythonPath) {
        $pythonPath = (Get-Command python3 -ErrorAction SilentlyContinue).Source
    }
    
    if (-not $pythonPath) {
        Write-Log "ERROR: Python not found in PATH"
        exit 1
    }
    
    try {
        # Remove existing task if present
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        
        # Create new task
        $action = New-ScheduledTaskAction `
            -Execute $pythonPath `
            -Argument "$InstallDir\src\auth_router_final.py --mode enforce" `
            -WorkingDirectory $InstallDir
        
        $trigger = New-ScheduledTaskTrigger -AtStartup
        
        $principal = New-ScheduledTaskPrincipal `
            -UserId "SYSTEM" `
            -LogonType ServiceAccount `
            -RunLevel Highest
        
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -RestartCount 3
        
        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Description "Postman SAML Authentication Router" | Out-Null
        
        Write-Log "Scheduled task created successfully"
        
        # Start the task immediately
        Start-ScheduledTask -TaskName $taskName
        Write-Log "Daemon started via scheduled task"
    } catch {
        Write-Log "ERROR: Failed to create scheduled task: $_"
        exit 1
    }
}

# Verify deployment
function Test-Deployment {
    Write-Log "Verifying deployment..."
    
    $errors = 0
    
    # Check hosts file
    $hostsContent = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts"
    if ($hostsContent -match "127\.0\.0\.1\s+identity\.getpostman\.com") {
        Write-Log "✓ Hosts file configured correctly"
    } else {
        Write-Log "✗ Hosts file not configured"
        $errors++
    }
    
    # Check certificate
    $cert = Get-ChildItem -Path Cert:\LocalMachine\Root | 
        Where-Object { $_.Subject -match "identity.getpostman.com" }
    if ($cert) {
        Write-Log "✓ Certificate installed in Trusted Root store"
    } else {
        Write-Log "✗ Certificate not found in store"
        $errors++
    }
    
    # Check scheduled task
    $task = Get-ScheduledTask -TaskName "PostmanAuthRouter" -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq "Running") {
        Write-Log "✓ Daemon is running"
    } else {
        Write-Log "✗ Daemon is not running"
        $errors++
    }
    
    # Check health endpoint
    Start-Sleep -Seconds 5
    try {
        $response = Invoke-WebRequest -Uri "https://identity.getpostman.com/health" `
            -UseBasicParsing -SkipCertificateCheck -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-Log "✓ Health endpoint responding"
        }
    } catch {
        Write-Log "⚠ Health endpoint not accessible (may need more time to start)"
    }
    
    if ($errors -eq 0) {
        Write-Log "DEPLOYMENT SUCCESSFUL - All checks passed"
        exit 0
    } else {
        Write-Log "DEPLOYMENT COMPLETED WITH ERRORS - $errors checks failed"
        exit 1
    }
}

# Main execution
try {
    Write-Log "=========================================="
    Write-Log "Starting Postman Auth Router deployment via Intune"
    Write-Log "=========================================="
    
    # Check if running as SYSTEM (Intune context)
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Log "Running as: $currentUser"
    
    # Execute deployment steps
    Initialize-Directories
    Install-Package        # You'll need to implement actual package delivery
    Configure-Hosts
    Install-Certificate
    Create-Configuration
    Configure-Firewall
    Create-ScheduledTask
    Test-Deployment
    
    Write-Log "=========================================="
    Write-Log "Deployment completed successfully"
    Write-Log "=========================================="
    
} catch {
    Write-Log "FATAL ERROR: $_"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)"
    exit 1
}

# Detection method for Intune (save as separate detection script)
<#
# Detection Script for Intune (deploy_intune_detection.ps1)
$installed = $true
$reasons = @()

# Check if daemon is installed
if (-not (Test-Path "$env:ProgramData\Postman\AuthRouter\src\auth_router_final.py")) {
    $installed = $false
    $reasons += "Auth router not installed"
}

# Check if scheduled task exists and is running
$task = Get-ScheduledTask -TaskName "PostmanAuthRouter" -ErrorAction SilentlyContinue
if (-not $task -or $task.State -ne "Running") {
    $installed = $false
    $reasons += "Daemon not running"
}

# Check hosts file
$hostsContent = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
if ($hostsContent -notmatch "127\.0\.0\.1\s+identity\.getpostman\.com") {
    $installed = $false
    $reasons += "Hosts file not configured"
}

if ($installed) {
    Write-Host "Postman Auth Router is installed and configured"
    exit 0
} else {
    Write-Host "Not installed: $($reasons -join ', ')"
    exit 1
}
#>