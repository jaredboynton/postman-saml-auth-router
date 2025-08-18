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

# Validate input parameters
function Test-InputParameters {
    Write-Log "Validating input parameters..."
    
    $validationPassed = $true
    
    # Validate PostmanTeamName
    if ($PostmanTeamName -notmatch '^[a-zA-Z0-9\-_]{2,50}$' -or $PostmanTeamName -eq '%POSTMAN_TEAM_NAME%') {
        Write-Log "Invalid PostmanTeamName: '$PostmanTeamName'. Must be 2-50 alphanumeric characters, hyphens, or underscores." -Level "ERROR"
        $validationPassed = $false
    }
    
    # Validate OktaTenantId
    if ($OktaTenantId -notmatch '^[a-zA-Z0-9\-_]{5,100}$' -or $OktaTenantId -eq '%OKTA_TENANT_ID%') {
        Write-Log "Invalid OktaTenantId: '$OktaTenantId'. Must be 5-100 alphanumeric characters, hyphens, or underscores." -Level "ERROR"
        $validationPassed = $false
    }
    
    # Validate IdpUrl
    if ($IdpUrl -notmatch '^https://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/.*)?$' -or $IdpUrl -eq '%IDP_URL%') {
        Write-Log "Invalid IdpUrl: '$IdpUrl'. Must be a valid HTTPS URL." -Level "ERROR"
        $validationPassed = $false
    }
    
    # Validate OktaAppId
    if ($OktaAppId -notmatch '^[a-zA-Z0-9]{10,50}$' -or $OktaAppId -eq '%OKTA_APP_ID%') {
        Write-Log "Invalid OktaAppId: '$OktaAppId'. Must be 10-50 alphanumeric characters." -Level "ERROR"
        $validationPassed = $false
    }
    
    # Validate URL accessibility (basic check)
    if ($validationPassed -and $IdpUrl -ne '%IDP_URL%') {
        try {
            $uri = [System.Uri]$IdpUrl
            if ($uri.Port -notin @(80, 443, 8080, 8443)) {
                Write-Log "Warning: IdpUrl uses non-standard port $($uri.Port). Ensure firewall allows this port." -Level "WARN"
            }
        } catch {
            Write-Log "Invalid IdpUrl format: $_" -Level "ERROR"
            $validationPassed = $false
        }
    }
    
    if (-not $validationPassed) {
        Write-Log "Parameter validation failed. Please check SCCM variable configuration." -Level "ERROR"
        return $false
    }
    
    Write-Log "Input parameter validation passed"
    return $true
}

# Check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    $prereqMet = $true
    
    # Check Python (primary requirement for daemon)
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
    # Set strict error handling for PowerShell
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'  # Suppress progress bars for better logging
    
    Write-Log "Starting installation of Postman Auth Router v$Version"
    
    # Validate input parameters
    try {
        if (-not (Test-InputParameters)) {
            Write-Log "Input validation failed" -Level "ERROR"
            return $ExitCodes.GeneralFailure
        }
    } catch {
        Write-Log "Input validation threw exception: $_" -Level "ERROR"
        return $ExitCodes.GeneralFailure
    }
    
    # Check prerequisites
    try {
        if (-not (Test-Prerequisites)) {
            Write-Log "Prerequisites not met" -Level "ERROR"
            return $ExitCodes.GeneralFailure
        }
    } catch {
        Write-Log "Prerequisites check threw exception: $_" -Level "ERROR"
        return $ExitCodes.GeneralFailure
    }
    
    try {
        # 1. Create installation directories
        Write-Log "Creating installation directories..."
        try {
            @($InstallDir, "$InstallDir\src", "$InstallDir\config", "$InstallDir\ssl", $LogDir) | ForEach-Object {
                if (-not (Test-Path $_)) {
                    New-Item -ItemType Directory -Path $_ -Force -ErrorAction Stop | Out-Null
                    Write-Log "Created directory: $_"
                } else {
                    Write-Log "Directory already exists: $_"
                }
            }
        } catch {
            Write-Log "Failed to create installation directories: $_" -Level "ERROR"
            throw "Directory creation failed: $_"
        }
        
        # 2. Copy files from SCCM content location
        Write-Log "Copying files from content location..."
        $contentPath = $PSScriptRoot
        
        try {
            # Verify source files exist before copying
            if (-not (Test-Path "$contentPath\src")) {
                throw "Source directory not found: $contentPath\src"
            }
            
            # Copy Python scripts
            Copy-Item "$contentPath\src\*" -Destination "$InstallDir\src\" -Recurse -Force -ErrorAction Stop
            Write-Log "Python scripts copied successfully"
            
            # Copy configuration template (optional - may not exist)
            if (Test-Path "$contentPath\config") {
                Copy-Item "$contentPath\config\*" -Destination "$InstallDir\config\" -Recurse -Force -ErrorAction Stop
                Write-Log "Configuration templates copied successfully"
            } else {
                Write-Log "Configuration templates not found in source - will create minimal config" -Level "WARN"
            }
            
            # Copy SSL configs (optional - may not exist)
            if (Test-Path "$contentPath\ssl\*.conf") {
                Copy-Item "$contentPath\ssl\*.conf" -Destination "$InstallDir\ssl\" -Force -ErrorAction Stop
                Write-Log "SSL configuration files copied successfully"
            } else {
                Write-Log "SSL configuration files not found in source - will generate minimal config" -Level "WARN"
            }
        } catch {
            Write-Log "Failed to copy installation files: $_" -Level "ERROR"
            throw "File copy operation failed: $_"
        }
        
        Write-Log "Files copied successfully"
        
        # 3. Configure hosts file
        Write-Log "Configuring hosts file..."
        $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
        $startMarker = "# BEGIN POSTMAN-AUTH-ROUTER-SCCM"
        $endMarker = "# END POSTMAN-AUTH-ROUTER-SCCM"
        
        $hostsContent = Get-Content $hostsFile -Raw
        if (-not ($hostsContent -match $startMarker)) {
            # Backup hosts file
            Copy-Item $hostsFile "$hostsFile.sccm_backup_$(Get-Date -Format 'yyyy-MM-dd-HHmmss')" -Force
            
            $entries = @"

$startMarker
127.0.0.1 identity.getpostman.com
127.0.0.1 identity.postman.co
$endMarker
"@
            Add-Content -Path $hostsFile -Value $entries
            Write-Log "Hosts file updated"
        }
        
        # 4. Setup SSL certificate (prioritize SCCM certificate profiles)
        Write-Log "Setting up SSL certificate..."
        
        # PREFERRED METHOD: Check for SCCM certificate deployment profile first
        $profileCert = Get-ChildItem -Path Cert:\LocalMachine\My | 
            Where-Object { $_.Subject -match "identity\.getpostman\.com" -and $_.Issuer -notmatch "identity\.getpostman\.com" } |
            Sort-Object NotAfter -Descending | Select-Object -First 1
            
        if ($profileCert) {
            Write-Log "Found certificate from SCCM certificate profile: $($profileCert.Thumbprint)"
            Write-Log "Certificate issued by: $($profileCert.Issuer)"
            Write-Log "Certificate expires: $($profileCert.NotAfter)"
            
            # Move certificate to Trusted Root if not already there
            $rootCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $profileCert.Thumbprint }
            if (-not $rootCert) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
                $store.Open("ReadWrite")
                $store.Add($profileCert)
                $store.Close()
                Write-Log "Certificate moved to Trusted Root store for SSL validation"
            }
            
            Write-Log "Using enterprise certificate from SCCM certificate profile (RECOMMENDED)"
        }
        # FALLBACK METHOD: Check for manual PFX certificate deployment
        elseif (Test-Path "$contentPath\certificates\enterprise.pfx") {
            Write-Log "No SCCM certificate profile found, attempting PFX certificate installation..."
            $enterpriseCert = "$contentPath\certificates\enterprise.pfx"
            Write-Log "Installing enterprise certificate..."
            
            # Use SCCM secure variables instead of hardcoded password
            try {
                # Method 1: Try SCCM task sequence variable
                $certPassword = $null
                if (Get-Command "Get-TSEnvironment" -ErrorAction SilentlyContinue) {
                    $tsEnv = New-Object -ComObject Microsoft.SMS.TSEnvironment
                    $certPasswordString = $tsEnv.Value("CertPassword")
                    if ($certPasswordString) {
                        $certPassword = ConvertTo-SecureString -String $certPasswordString -Force -AsPlainText
                        Write-Log "Using certificate password from SCCM task sequence variable"
                    }
                }
                
                # Method 2: Try SCCM application variable
                if (-not $certPassword) {
                    $certPasswordString = [System.Environment]::GetEnvironmentVariable("SCCM_CERT_PASSWORD")
                    if ($certPasswordString) {
                        $certPassword = ConvertTo-SecureString -String $certPasswordString -Force -AsPlainText
                        Write-Log "Using certificate password from SCCM environment variable"
                    }
                }
                
                # Method 3: Try registry variable (set by SCCM)
                if (-not $certPassword) {
                    $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution\Execution History\System\*" -Name "CertPassword" -ErrorAction SilentlyContinue
                    if ($regValue.CertPassword) {
                        $certPassword = ConvertTo-SecureString -String $regValue.CertPassword -Force -AsPlainText
                        Write-Log "Using certificate password from SCCM registry"
                    }
                }
                
                # Fallback: Check for separate password file
                if (-not $certPassword) {
                    $passwordFile = "$contentPath\certificates\cert.pwd"
                    if (Test-Path $passwordFile) {
                        $certPasswordString = Get-Content $passwordFile -Raw | Where-Object { $_.Trim() }
                        $certPassword = ConvertTo-SecureString -String $certPasswordString -Force -AsPlainText
                        Write-Log "Using certificate password from secure file"
                    }
                }
                
                if ($certPassword) {
                    $cert = Import-PfxCertificate -FilePath $enterpriseCert -CertStoreLocation "Cert:\LocalMachine\Root" -Password $certPassword
                    Write-Log "Enterprise certificate installed: $($cert.Thumbprint)"
                } else {
                    Write-Log "Certificate password not found in SCCM variables. Consider using SCCM certificate profiles instead." -Level "WARN"
                    Write-Log "Skipping PFX import - deploy certificate via SCCM certificate profile for better security" -Level "WARN"
                }
            } catch {
                Write-Log "Failed to import enterprise certificate: $_" -Level "ERROR"
                Write-Log "Consider deploying certificate via SCCM certificate profiles instead of PFX files" -Level "WARN"
            }
        } else {
            # LAST RESORT: Generate self-signed certificate
            Write-Log "No SCCM certificate profile or PFX certificate found" -Level "WARN"
            Write-Log "RECOMMENDATION: Deploy certificates via SCCM certificate profiles for better security and management" -Level "WARN"
            Write-Log "Falling back to self-signed certificate generation..." -Level "WARN"
            
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
`$scriptPath = "$InstallDir\src\saml_enforcer.py"
Start-Process -FilePath `$pythonPath -ArgumentList "`$scriptPath --mode enforce" -NoNewWindow -Wait
"@
        $serviceScript | Out-File -FilePath "$InstallDir\service_wrapper.ps1" -Encoding UTF8
        
        # Use NSSM (Non-Sucking Service Manager) for robust Windows service management
        $nssmPath = "$contentPath\tools\nssm.exe"
        $nssmInstalled = $false
        
        # Check for bundled NSSM or download it
        if (Test-Path $nssmPath) {
            Write-Log "Using bundled NSSM"
            $nssmInstalled = $true
        } else {
            # Download NSSM from official source with retry logic
            $nssmDownloaded = $false
            $retryCount = 0
            $maxRetries = 3
            $retryDelays = @(1, 2, 4)  # Exponential backoff in seconds
            
            while (-not $nssmDownloaded -and $retryCount -lt $maxRetries) {
                try {
                    if ($retryCount -gt 0) {
                        Write-Log "NSSM download retry attempt $retryCount of $maxRetries after $($retryDelays[$retryCount-1]) seconds..."
                        Start-Sleep -Seconds $retryDelays[$retryCount-1]
                    }
                    
                    Write-Log "Downloading NSSM (Non-Sucking Service Manager)..."
                    $nssmUrl = "https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip"
                    $nssmZip = "$env:TEMP\nssm.zip"
                    $nssmExtract = "$env:TEMP\nssm"
                    
                    # Add timeout and user agent for better reliability
                    Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing -TimeoutSec 60 -UserAgent "PostmanAuthRouter-SCCM/1.0"
                    
                    # Verify download
                    if ((Get-Item $nssmZip -ErrorAction SilentlyContinue).Length -gt 1000) {
                        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force
                        $nssmDownloaded = $true
                        Write-Log "NSSM download completed successfully"
                    } else {
                        throw "Downloaded file appears incomplete or corrupt"
                    }
                    
                } catch {
                    $retryCount++
                    Write-Log "NSSM download attempt failed: $_" -Level "WARN"
                    if ($retryCount -ge $maxRetries) {
                        Write-Log "Failed to download NSSM after $maxRetries attempts. Falling back to scheduled task." -Level "WARN"
                        break
                    }
                    # Clean up failed download
                    Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
                    Remove-Item $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            
            # Process downloaded NSSM if successful
            if ($nssmDownloaded -and (Test-Path $nssmExtract)) {
                try {
                    # Find the appropriate architecture NSSM executable
                    $arch = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
                    $extractedNssm = Get-ChildItem -Path $nssmExtract -Recurse -Name "nssm.exe" | 
                        Where-Object { $_ -match $arch } | Select-Object -First 1
                    
                    if ($extractedNssm) {
                        $nssmPath = Join-Path $nssmExtract (Split-Path $extractedNssm -Parent) "nssm.exe"
                        Copy-Item $nssmPath "$InstallDir\nssm.exe" -Force
                        $nssmPath = "$InstallDir\nssm.exe"
                        $nssmInstalled = $true
                        Write-Log "NSSM extracted and installed successfully"
                    } else {
                        Write-Log "NSSM executable not found in downloaded archive" -Level "WARN"
                    }
                } catch {
                    Write-Log "Failed to extract NSSM: $_" -Level "WARN"
                } finally {
                    # Cleanup regardless of success/failure
                    Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
                    Remove-Item $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        if ($nssmInstalled) {
            # Install service using NSSM
            Write-Log "Creating Windows service with NSSM..."
            
            # Remove existing service if present
            & $nssmPath remove $serviceName confirm 2>$null
            
            # Install service
            & $nssmPath install $serviceName $pythonPath "`"$InstallDir\src\saml_enforcer.py`"" "--mode" "enforce"
            
            # Configure service settings
            & $nssmPath set $serviceName DisplayName "Postman SAML Authentication Router"
            & $nssmPath set $serviceName Description "Enforces SAML authentication for Postman applications via DNS interception"
            & $nssmPath set $serviceName Start SERVICE_AUTO_START
            & $nssmPath set $serviceName AppDirectory $InstallDir
            & $nssmPath set $serviceName AppStdout "$LogDir\nssm_stdout.log"
            & $nssmPath set $serviceName AppStderr "$LogDir\nssm_stderr.log"
            & $nssmPath set $serviceName AppRotateFiles 1
            & $nssmPath set $serviceName AppRotateOnline 1
            & $nssmPath set $serviceName AppRotateSeconds 86400
            & $nssmPath set $serviceName AppRotateBytes 10485760
            
            # Configure failure recovery
            & $nssmPath set $serviceName AppExit Default Restart
            & $nssmPath set $serviceName AppRestartDelay 5000
            & $nssmPath set $serviceName AppStopMethodSkip 0
            & $nssmPath set $serviceName AppStopMethodConsole 1500
            & $nssmPath set $serviceName AppStopMethodWindow 1500
            & $nssmPath set $serviceName AppStopMethodThreads 1500
            & $nssmPath set $serviceName AppKillProcessTree 1
            
            # Set service to restart on failure
            & $nssmPath set $serviceName AppThrottle 1500
            
            Write-Log "NSSM service configured with restart policies and crash recovery"
            
            # Start the service
            & $nssmPath start $serviceName
            Write-Log "Windows service started via NSSM"
            
        } else {
            # Fallback to scheduled task if NSSM is not available
            Write-Log "NSSM not available, falling back to scheduled task" -Level "WARN"
            
            $action = New-ScheduledTaskAction `
                -Execute $pythonPath `
                -Argument "`"$InstallDir\src\saml_enforcer.py`" --mode enforce" `
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
                -Description "Postman SAML Authentication Router (SCCM Deployed - Fallback)" `
                -Force | Out-Null
            
            Start-ScheduledTask -TaskName $serviceName
            Write-Log "Scheduled task created as fallback"
        }
        
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
        $nssmPath = "$InstallDir\nssm.exe"
        
        # Try to remove NSSM service first
        if (Test-Path $nssmPath) {
            Write-Log "Stopping and removing NSSM service..."
            & $nssmPath stop $serviceName 2>$null
            & $nssmPath remove $serviceName confirm 2>$null
            Write-Log "NSSM service removed"
        } else {
            # Check if service exists through Windows Service Manager
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                Write-Log "Stopping Windows service..."
                Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                # Try sc.exe for removal if NSSM is not available
                & sc.exe delete $serviceName 2>$null
                Write-Log "Windows service removed"
            }
        }
        
        # Also remove scheduled task (for fallback scenarios)
        Stop-ScheduledTask -TaskName $serviceName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $serviceName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Scheduled task cleanup completed"
        
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
    
    # Check service/scheduled task (prioritize NSSM service)
    $serviceRunning = $false
    $serviceDetails = ""
    
    # Check for NSSM service first
    $service = Get-Service -Name "PostmanAuthRouter" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        $serviceRunning = $true
        $serviceDetails = "NSSM service running"
    } else {
        # Fallback to scheduled task check
        $task = Get-ScheduledTask -TaskName "PostmanAuthRouter" -ErrorAction SilentlyContinue
        if ($task -and $task.State -eq "Running") {
            $serviceRunning = $true
            $serviceDetails = "Scheduled task running"
        }
    }
    
    if ($serviceRunning) {
        $details += $serviceDetails
    } else {
        $installed = $false
        $details += "Service/task not running"
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