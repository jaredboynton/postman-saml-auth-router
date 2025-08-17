#############################################################################
# Postman SAML Authentication Router - SCCM Deployment Script
# 
# This script deploys the Postman authentication daemon via Microsoft SCCM
# Deploy as Application or Package in Configuration Manager
#
# Version: 1.0
# Date: 2025-08-17
#############################################################################

param(
    [Parameter(Mandatory=$false)]
    [string]$Mode = "Install",  # Install, Uninstall, or Repair
    
    [Parameter(Mandatory=$false)]
    [string]$PostmanTeamName = "%POSTMAN_TEAM_NAME%",  # Will be replaced by SCCM
    
    [Parameter(Mandatory=$false)]
    [string]$OktaTenantId = "%OKTA_TENANT_ID%",
    
    [Parameter(Mandatory=$false)]
    [string]$IdpUrl = "%IDP_URL%",
    
    [Parameter(Mandatory=$false)]
    [string]$OktaAppId = "%OKTA_APP_ID%"
)

# SCCM Exit Codes
$ExitCodes = @{
    Success = 0
    RebootRequired = 3010
    HardRebootRequired = 1641
    FastRebootRequired = 1604
    GeneralFailure = 1603
}

# Configuration
$InstallDir = "$env:ProgramData\Postman\AuthRouter"
$LogDir = "$env:ProgramData\Postman\logs"
$LogFile = "$LogDir\sccm_deployment.log"
$RegistryPath = "HKLM:\SOFTWARE\Postman\AuthRouter"
$Version = "1.0.0"

# Initialize logging
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    $logEntry | Out-File -FilePath $LogFile -Append
    
    # Also write to SCCM log format
    $ccmLogEntry = "<![LOG[$Message]LOG]!><time=`"$(Get-Date -Format 'HH:mm:ss.fff')+000`" date=`"$(Get-Date -Format 'MM-dd-yyyy')`" component=`"PostmanAuthRouter`" context=`"`" type=`"1`" thread=`"$PID`" file=`"deploy_sccm.ps1`">"
    $ccmLogEntry | Out-File -FilePath "$LogDir\PostmanAuthRouter.log" -Append -Encoding UTF8
    
    Write-Host "[$Level] $Message"
}

# Check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    $prereqMet = $true
    
    # Check .NET Framework
    $dotNet = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name Release -ErrorAction SilentlyContinue
    if ($dotNet.Release -lt 461808) {
        Write-Log ".NET Framework 4.7.2 or higher required" -Level "ERROR"
        $prereqMet = $false
    }
    
    # Check Python
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        $python = Get-Command python3 -ErrorAction SilentlyContinue
    }
    if (-not $python) {
        Write-Log "Python 3 is not installed" -Level "ERROR"
        $prereqMet = $false
    } else {
        Write-Log "Python found at: $($python.Source)"
    }
    
    # Check Windows version
    $os = Get-WmiObject -Class Win32_OperatingSystem
    if ([version]$os.Version -lt [version]"10.0") {
        Write-Log "Windows 10 or higher required" -Level "ERROR"
        $prereqMet = $false
    }
    
    return $prereqMet
}

# Install function
function Install-PostmanAuthRouter {
    Write-Log "Starting installation of Postman Auth Router v$Version"
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites not met" -Level "ERROR"
        return $ExitCodes.GeneralFailure
    }
    
    try {
        # 1. Create installation directories
        Write-Log "Creating installation directories..."
        @($InstallDir, "$InstallDir\src", "$InstallDir\config", "$InstallDir\ssl", $LogDir) | ForEach-Object {
            if (-not (Test-Path $_)) {
                New-Item -ItemType Directory -Path $_ -Force | Out-Null
                Write-Log "Created directory: $_"
            }
        }
        
        # 2. Copy files from SCCM content location
        Write-Log "Copying files from content location..."
        $contentPath = $PSScriptRoot
        
        # Copy Python scripts
        Copy-Item "$contentPath\src\*" -Destination "$InstallDir\src\" -Recurse -Force
        
        # Copy configuration template
        Copy-Item "$contentPath\config\*" -Destination "$InstallDir\config\" -Recurse -Force
        
        # Copy SSL configs
        Copy-Item "$contentPath\ssl\*.conf" -Destination "$InstallDir\ssl\" -Force
        
        Write-Log "Files copied successfully"
        
        # 3. Configure hosts file
        Write-Log "Configuring hosts file..."
        $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
        $startMarker = "# BEGIN POSTMAN-AUTH-ROUTER-SCCM"
        $endMarker = "# END POSTMAN-AUTH-ROUTER-SCCM"
        
        $hostsContent = Get-Content $hostsFile -Raw
        if (-not ($hostsContent -match $startMarker)) {
            # Backup hosts file
            Copy-Item $hostsFile "$hostsFile.sccm_backup_$(Get-Date -Format 'yyyyMMddHHmmss')" -Force
            
            $entries = @"

$startMarker
127.0.0.1 identity.getpostman.com
127.0.0.1 identity.postman.co
$endMarker
"@
            Add-Content -Path $hostsFile -Value $entries
            Write-Log "Hosts file updated"
        }
        
        # 4. Generate or install certificate
        Write-Log "Setting up SSL certificate..."
        
        # Check for enterprise certificate from SCCM
        $enterpriseCert = "$contentPath\certificates\enterprise.pfx"
        if (Test-Path $enterpriseCert) {
            Write-Log "Installing enterprise certificate..."
            $certPassword = ConvertTo-SecureString -String "YourCertPassword" -Force -AsPlainText
            $cert = Import-PfxCertificate -FilePath $enterpriseCert -CertStoreLocation "Cert:\LocalMachine\Root" -Password $certPassword
            Write-Log "Enterprise certificate installed: $($cert.Thumbprint)"
        } else {
            # Generate self-signed certificate
            Write-Log "Generating self-signed certificate..."
            
            # Use OpenSSL if bundled
            $opensslPath = "$contentPath\tools\openssl.exe"
            if (Test-Path $opensslPath) {
                & $opensslPath req -new -x509 -days 365 -nodes `
                    -out "$InstallDir\ssl\cert.pem" `
                    -keyout "$InstallDir\ssl\key.pem" `
                    -config "$InstallDir\ssl\cert.conf" `
                    -extensions v3_req 2>&1 | Out-Null
                
                # Trust the certificate
                certutil -addstore -f "Root" "$InstallDir\ssl\cert.pem" | Out-Null
                Write-Log "Self-signed certificate generated and trusted"
            } else {
                # Use PowerShell as fallback
                $cert = New-SelfSignedCertificate `
                    -Subject "CN=identity.getpostman.com" `
                    -DnsName @("identity.getpostman.com", "identity.postman.com", "identity.postman.co", "localhost") `
                    -CertStoreLocation "Cert:\LocalMachine\My" `
                    -NotAfter (Get-Date).AddYears(1) `
                    -KeyExportPolicy Exportable
                
                # Move to Trusted Root
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
                $store.Open("ReadWrite")
                $store.Add($cert)
                $store.Close()
                
                Write-Log "PowerShell certificate generated: $($cert.Thumbprint)"
            }
        }
        
        # 5. Create configuration file
        Write-Log "Creating configuration file..."
        $config = @{
            postman_team_name = $PostmanTeamName -replace '%.*%', ''
            okta_tenant_id = $OktaTenantId -replace '%.*%', ''
            idp_config = @{
                idp_type = "okta"
                idp_url = $IdpUrl -replace '%.*%', ''
                okta_app_id = $OktaAppId -replace '%.*%', ''
            }
            advanced = @{
                log_file = "$LogDir\postman-auth.log"
                daemon_port = 443
                health_port = 8443
            }
        }
        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath "$InstallDir\config\config.json" -Encoding UTF8
        Write-Log "Configuration created"
        
        # 6. Configure Windows Firewall
        Write-Log "Configuring Windows Firewall..."
        New-NetFirewallRule `
            -DisplayName "Postman Auth Router (SCCM)" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 443 `
            -Action Allow `
            -Profile Any `
            -ErrorAction SilentlyContinue | Out-Null
        
        # 7. Create Windows Service
        Write-Log "Creating Windows Service..."
        $serviceName = "PostmanAuthRouter"
        $pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
        if (-not $pythonPath) {
            $pythonPath = (Get-Command python3 -ErrorAction SilentlyContinue).Source
        }
        
        # Create service wrapper script
        $serviceScript = @"
`$pythonPath = "$pythonPath"
`$scriptPath = "$InstallDir\src\auth_router_final.py"
Start-Process -FilePath `$pythonPath -ArgumentList "`$scriptPath --mode enforce" -NoNewWindow -Wait
"@
        $serviceScript | Out-File -FilePath "$InstallDir\service_wrapper.ps1" -Encoding UTF8
        
        # Use NSSM or scheduled task as alternative to Windows Service
        # For simplicity, using scheduled task here
        $action = New-ScheduledTaskAction `
            -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -File `"$InstallDir\service_wrapper.ps1`"" `
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
            -RestartCount 3 `
            -ExecutionTimeLimit (New-TimeSpan -Hours 0)
        
        Register-ScheduledTask `
            -TaskName $serviceName `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Description "Postman SAML Authentication Router (SCCM Deployed)" `
            -Force | Out-Null
        
        Write-Log "Scheduled task created"
        
        # Start the service
        Start-ScheduledTask -TaskName $serviceName
        Write-Log "Service started"
        
        # 8. Create registry entries for SCCM detection
        Write-Log "Creating registry entries..."
        if (-not (Test-Path $RegistryPath)) {
            New-Item -Path $RegistryPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $RegistryPath -Name "Version" -Value $Version
        Set-ItemProperty -Path $RegistryPath -Name "InstallDate" -Value (Get-Date -Format "yyyy-MM-dd")
        Set-ItemProperty -Path $RegistryPath -Name "InstallPath" -Value $InstallDir
        Set-ItemProperty -Path $RegistryPath -Name "TeamName" -Value $PostmanTeamName
        
        Write-Log "Registry entries created"
        
        # 9. Verify installation
        Start-Sleep -Seconds 5
        $task = Get-ScheduledTask -TaskName $serviceName -ErrorAction SilentlyContinue
        if ($task -and $task.State -eq "Running") {
            Write-Log "Installation completed successfully"
            return $ExitCodes.Success
        } else {
            Write-Log "Service failed to start" -Level "ERROR"
            return $ExitCodes.GeneralFailure
        }
        
    } catch {
        Write-Log "Installation failed: $_" -Level "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
        return $ExitCodes.GeneralFailure
    }
}

# Uninstall function
function Uninstall-PostmanAuthRouter {
    Write-Log "Starting uninstallation of Postman Auth Router"
    
    try {
        # 1. Stop and remove service/scheduled task
        $serviceName = "PostmanAuthRouter"
        Stop-ScheduledTask -TaskName $serviceName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $serviceName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Service removed"
        
        # 2. Remove hosts entries
        $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
        $startMarker = "# BEGIN POSTMAN-AUTH-ROUTER-SCCM"
        $endMarker = "# END POSTMAN-AUTH-ROUTER-SCCM"
        
        $hostsContent = Get-Content $hostsFile -Raw
        if ($hostsContent -match $startMarker) {
            $pattern = "(?ms)$([regex]::Escape($startMarker)).*?$([regex]::Escape($endMarker))\r?\n?"
            $newContent = $hostsContent -replace $pattern, ""
            Set-Content -Path $hostsFile -Value $newContent -NoNewline
            Write-Log "Hosts entries removed"
        }
        
        # 3. Remove certificates
        Get-ChildItem -Path Cert:\LocalMachine\Root | 
            Where-Object { $_.Subject -match "identity.getpostman.com" } | 
            Remove-Item -Force
        Write-Log "Certificates removed"
        
        # 4. Remove firewall rule
        Remove-NetFirewallRule -DisplayName "Postman Auth Router (SCCM)" -ErrorAction SilentlyContinue
        Write-Log "Firewall rule removed"
        
        # 5. Remove installation directory
        if (Test-Path $InstallDir) {
            Remove-Item -Path $InstallDir -Recurse -Force
            Write-Log "Installation directory removed"
        }
        
        # 6. Remove registry entries
        if (Test-Path $RegistryPath) {
            Remove-Item -Path $RegistryPath -Recurse -Force
            Write-Log "Registry entries removed"
        }
        
        # 7. Flush DNS cache
        ipconfig /flushdns | Out-Null
        Write-Log "DNS cache flushed"
        
        Write-Log "Uninstallation completed successfully"
        return $ExitCodes.Success
        
    } catch {
        Write-Log "Uninstallation failed: $_" -Level "ERROR"
        return $ExitCodes.GeneralFailure
    }
}

# Repair function
function Repair-PostmanAuthRouter {
    Write-Log "Starting repair of Postman Auth Router"
    
    # Uninstall then reinstall
    $uninstallResult = Uninstall-PostmanAuthRouter
    if ($uninstallResult -eq $ExitCodes.Success) {
        return Install-PostmanAuthRouter
    } else {
        return $uninstallResult
    }
}

# Detection method (for SCCM Application model)
function Test-Installation {
    $installed = $true
    $details = @()
    
    # Check registry
    if (Test-Path $RegistryPath) {
        $regVersion = Get-ItemProperty -Path $RegistryPath -Name "Version" -ErrorAction SilentlyContinue
        if ($regVersion.Version -eq $Version) {
            $details += "Registry version matches"
        } else {
            $installed = $false
            $details += "Registry version mismatch"
        }
    } else {
        $installed = $false
        $details += "Registry not found"
    }
    
    # Check scheduled task
    $task = Get-ScheduledTask -TaskName "PostmanAuthRouter" -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq "Running") {
        $details += "Service running"
    } else {
        $installed = $false
        $details += "Service not running"
    }
    
    # Check hosts file
    $hostsContent = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
    if ($hostsContent -match "127\.0\.0\.1\s+identity\.getpostman\.com") {
        $details += "Hosts configured"
    } else {
        $installed = $false
        $details += "Hosts not configured"
    }
    
    # Check certificate
    $cert = Get-ChildItem -Path Cert:\LocalMachine\Root | 
        Where-Object { $_.Subject -match "identity.getpostman.com" }
    if ($cert) {
        $details += "Certificate installed"
    } else {
        $installed = $false
        $details += "Certificate not found"
    }
    
    if ($installed) {
        Write-Log "Detection: Installed - $($details -join ', ')"
        return $true
    } else {
        Write-Log "Detection: Not installed - $($details -join ', ')"
        return $false
    }
}

# Main execution
Write-Log "=========================================="
Write-Log "Postman Auth Router SCCM Deployment Script"
Write-Log "Mode: $Mode"
Write-Log "=========================================="

$exitCode = $ExitCodes.GeneralFailure

switch ($Mode.ToLower()) {
    "install" {
        $exitCode = Install-PostmanAuthRouter
    }
    "uninstall" {
        $exitCode = Uninstall-PostmanAuthRouter
    }
    "repair" {
        $exitCode = Repair-PostmanAuthRouter
    }
    "detect" {
        if (Test-Installation) {
            $exitCode = $ExitCodes.Success
        } else {
            $exitCode = 1
        }
    }
    default {
        Write-Log "Invalid mode: $Mode" -Level "ERROR"
        Write-Log "Valid modes: Install, Uninstall, Repair, Detect"
    }
}

Write-Log "Exiting with code: $exitCode"
exit $exitCode