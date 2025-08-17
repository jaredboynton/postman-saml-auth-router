#############################################################################
# Postman Auth Daemon Manager for Windows
# Handles certificate trust and daemon lifecycle management
#
# Usage: .\daemon_manager.ps1 <command>
# Run as Administrator for all commands
#############################################################################

param(
    [Parameter(Position=0)]
    [string]$Command = "help"
)

# Colors and formatting
$Script:Colors = @{
    Red = "Red"
    Green = "Green"
    Yellow = "Yellow"
    Blue = "Cyan"
    Default = "White"
}

# Configuration
$Script:Config = @{
    InstallDir = "$env:ProgramData\Postman\AuthRouter"
    LogDir = "$env:ProgramData\Postman\logs"
    LogFile = "$env:ProgramData\Postman\logs\postman-auth.log"
    CertDir = "ssl"
    CertFile = "ssl\cert.pem"
    KeyFile = "ssl\key.pem"
    CertDays = 365
    HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    StartMarker = "# BEGIN POSTMAN-AUTH-ROUTER"
    EndMarker = "# END POSTMAN-AUTH-ROUTER"
    PidFile = "$env:ProgramData\Postman\daemon.pid"
}

# Markers for safe hosts file management
$START_MARKER = "# BEGIN POSTMAN-AUTH-ROUTER"
$END_MARKER = "# END POSTMAN-AUTH-ROUTER"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "Default",
        [switch]$NoNewline
    )
    
    $params = @{
        Object = $Message
        ForegroundColor = $Script:Colors[$Color]
    }
    if ($NoNewline) {
        $params.NoNewline = $true
    }
    Write-Host @params
}

function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Dependencies {
    Write-ColorOutput "Checking dependencies..." -Color Blue
    $missing = $false
    
    # Check Python 3
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        $python = Get-Command python3 -ErrorAction SilentlyContinue
    }
    
    if ($python) {
        $pyVersion = & $python.Source --version 2>&1
        Write-ColorOutput "✓ Python found: $pyVersion" -Color Green
        $Script:PythonPath = $python.Source
    } else {
        Write-ColorOutput "✗ Python 3 is required but not installed" -Color Red
        Write-ColorOutput "  Download from: https://www.python.org/downloads/" -Color Yellow
        $missing = $true
    }
    
    # Check OpenSSL (optional)
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($openssl) {
        Write-ColorOutput "✓ OpenSSL found" -Color Green
        $Script:OpenSSLPath = $openssl.Source
    } else {
        Write-ColorOutput "⚠ OpenSSL not found (will use PowerShell for certificates)" -Color Yellow
    }
    
    # Check if running as Administrator
    if (-not (Test-Administrator)) {
        Write-ColorOutput "✗ Administrator privileges required" -Color Red
        $missing = $true
    }
    
    return -not $missing
}

function Start-Daemon {
    Write-ColorOutput "Starting Postman Auth Daemon..." -Color Green
    
    # Check for existing daemon
    $existingProcess = Get-Process -Name python* -ErrorAction SilentlyContinue | 
        Where-Object { $_.CommandLine -like "*auth_router*" }
    
    if ($existingProcess) {
        Write-ColorOutput "Found existing daemon, stopping it..." -Color Yellow
        Stop-Process -Id $existingProcess.Id -Force
        Start-Sleep -Seconds 2
    }
    
    # Check port 443
    $port443 = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
    if ($port443) {
        Write-ColorOutput "Port 443 is in use, attempting to free it..." -Color Yellow
        $process = Get-Process -Id $port443.OwningProcess -ErrorAction SilentlyContinue
        if ($process) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }
    
    # Create log directory if needed
    if (-not (Test-Path $Script:Config.LogDir)) {
        New-Item -ItemType Directory -Path $Script:Config.LogDir -Force | Out-Null
    }
    
    # Start daemon as background process
    Write-ColorOutput "Starting daemon in ENFORCE mode..." -Color Green
    $scriptPath = Join-Path (Get-Location) "src\auth_router_final.py"
    
    if (-not (Test-Path $scriptPath)) {
        Write-ColorOutput "✗ auth_router_final.py not found at: $scriptPath" -Color Red
        exit 1
    }
    
    # Start Python daemon
    $processInfo = Start-Process -FilePath $Script:PythonPath `
        -ArgumentList "$scriptPath --mode enforce" `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput $Script:Config.LogFile `
        -RedirectStandardError "$($Script:Config.LogFile).error"
    
    # Save PID
    $processInfo.Id | Out-File -FilePath $Script:Config.PidFile -Force
    
    Start-Sleep -Seconds 3
    
    # Check if daemon started
    if (Get-Process -Id $processInfo.Id -ErrorAction SilentlyContinue) {
        Write-ColorOutput "✓ Daemon started successfully (PID: $($processInfo.Id))" -Color Green
        Write-ColorOutput "Test with: curl -k https://identity.getpostman.com/health" -Color Default
    } else {
        Write-ColorOutput "✗ Failed to start daemon" -Color Red
        if (Test-Path "$($Script:Config.LogFile).error") {
            Write-ColorOutput "Error log:" -Color Red
            Get-Content "$($Script:Config.LogFile).error" -Tail 10
        }
        exit 1
    }
}

function Stop-Daemon {
    Write-ColorOutput "Stopping Postman Auth Daemon..." -Color Yellow
    
    # Try to read PID file first
    if (Test-Path $Script:Config.PidFile) {
        $pid = Get-Content $Script:Config.PidFile -ErrorAction SilentlyContinue
        if ($pid) {
            $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($process) {
                Stop-Process -Id $pid -Force
                Write-ColorOutput "✓ Daemon stopped (PID: $pid)" -Color Green
                Remove-Item $Script:Config.PidFile -Force
                return
            }
        }
    }
    
    # Fallback: find by command line
    $processes = Get-Process -Name python* -ErrorAction SilentlyContinue
    foreach ($proc in $processes) {
        try {
            $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
            if ($cmdLine -like "*auth_router*") {
                Stop-Process -Id $proc.Id -Force
                Write-ColorOutput "✓ Daemon stopped (PID: $($proc.Id))" -Color Green
            }
        } catch {
            # Process might have already exited
        }
    }
    
    if (Test-Path $Script:Config.PidFile) {
        Remove-Item $Script:Config.PidFile -Force
    }
}

function Get-DaemonStatus {
    $running = $false
    $pid = $null
    
    # Check PID file
    if (Test-Path $Script:Config.PidFile) {
        $pid = Get-Content $Script:Config.PidFile -ErrorAction SilentlyContinue
        if ($pid) {
            $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($process) {
                $running = $true
            }
        }
    }
    
    if ($running) {
        Write-ColorOutput "✓ Daemon is running (PID: $pid)" -Color Green
        Write-ColorOutput ""
        Write-ColorOutput "Health check:" -Color Default
        try {
            $response = Invoke-WebRequest -Uri "https://identity.getpostman.com/health" -UseBasicParsing -SkipCertificateCheck
            $response.Content | ConvertFrom-Json | ConvertTo-Json -Depth 10
        } catch {
            Write-ColorOutput "Could not reach health endpoint" -Color Yellow
        }
    } else {
        Write-ColorOutput "✗ Daemon is not running" -Color Red
    }
}

function Show-Logs {
    Write-ColorOutput "Showing daemon logs..." -Color Green
    Write-ColorOutput "Press Ctrl+C to stop viewing logs" -Color Default
    Write-ColorOutput ""
    
    if (Test-Path $Script:Config.LogFile) {
        Get-Content $Script:Config.LogFile -Wait
    } else {
        Write-ColorOutput "No log file found at: $($Script:Config.LogFile)" -Color Yellow
    }
}

function Manage-Certificates {
    Write-ColorOutput "Managing SSL Certificates..." -Color Green
    Write-ColorOutput ""
    
    $certPath = Join-Path (Get-Location) $Script:Config.CertFile
    $keyPath = Join-Path (Get-Location) $Script:Config.KeyFile
    $certDir = Join-Path (Get-Location) $Script:Config.CertDir
    
    # 1. Check if certificates exist
    if ((Test-Path $certPath) -and (Test-Path $keyPath)) {
        Write-ColorOutput "✓ Certificates found:" -Color Green
        Write-ColorOutput "  Certificate: $certPath" -Color Default
        Write-ColorOutput "  Private Key: $keyPath" -Color Default
        
        # Check certificate validity (if OpenSSL available)
        if ($Script:OpenSSLPath) {
            $certInfo = & $Script:OpenSSLPath x509 -enddate -noout -in $certPath 2>$null
            if ($certInfo) {
                Write-ColorOutput "  $certInfo" -Color Default
            }
        }
        Write-ColorOutput ""
        
        # 2. Check if trusted in Windows store
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $store.Open("ReadOnly")
        $trusted = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        $store.Close()
        
        if ($trusted) {
            Write-ColorOutput "✓ Certificate is already trusted in Windows Certificate Store" -Color Green
            Write-ColorOutput ""
            Write-ColorOutput "No action needed - certificates are ready!" -Color Default
        } else {
            Write-ColorOutput "⚠ Certificate exists but is NOT trusted" -Color Yellow
            Write-ColorOutput ""
            Write-ColorOutput "Adding certificate to Windows Certificate Store..." -Color Default
            
            # Import certificate to Trusted Root store
            $certutil = certutil -addstore -f "Root" $certPath 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-ColorOutput "✓ Certificate now trusted!" -Color Green
            } else {
                Write-ColorOutput "✗ Failed to trust certificate: $certutil" -Color Red
                exit 1
            }
        }
    } else {
        # 3. Certificates don't exist - generate them
        Write-ColorOutput "No certificates found. Generating new certificates..." -Color Yellow
        Write-ColorOutput ""
        
        # Create SSL directory if needed
        if (-not (Test-Path $certDir)) {
            Write-ColorOutput "Creating SSL directory..." -Color Default
            New-Item -ItemType Directory -Path $certDir -Force | Out-Null
        }
        
        # Check for cert.conf
        $certConf = Join-Path $certDir "cert.conf"
        if (-not (Test-Path $certConf)) {
            Write-ColorOutput "✗ Certificate configuration not found at $certConf" -Color Red
            Write-ColorOutput "This file is required for certificate generation" -Color Red
            exit 1
        }
        
        Write-ColorOutput "Generating self-signed certificate (valid for $($Script:Config.CertDays) days)..." -Color Default
        
        if ($Script:OpenSSLPath) {
            # Use OpenSSL if available
            $result = & $Script:OpenSSLPath req -new -x509 -days $Script:Config.CertDays -nodes `
                -out $certPath `
                -keyout $keyPath `
                -config $certConf `
                -extensions v3_req 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-ColorOutput "✓ Certificates generated successfully!" -Color Green
            } else {
                Write-ColorOutput "✗ Certificate generation failed: $result" -Color Red
                exit 1
            }
        } else {
            # Fallback to PowerShell (limited SAN support)
            Write-ColorOutput "Using PowerShell to generate certificate (limited SAN support)..." -Color Yellow
            
            $dnsNames = @(
                "identity.getpostman.com",
                "identity.postman.com", 
                "identity.postman.co",
                "id.gw.postman.com",
                "localhost"
            )
            
            # Create self-signed certificate
            $cert = New-SelfSignedCertificate `
                -Subject "CN=identity.getpostman.com" `
                -DnsName $dnsNames `
                -CertStoreLocation "Cert:\LocalMachine\My" `
                -NotAfter (Get-Date).AddDays($Script:Config.CertDays) `
                -KeyExportPolicy Exportable `
                -KeySpec KeyExchange `
                -KeyUsage DigitalSignature, KeyEncipherment, DataEncipherment `
                -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
            
            # Export certificate
            $certPassword = ConvertTo-SecureString -String "TempPassword123!" -Force -AsPlainText
            Export-PfxCertificate -Cert $cert -FilePath "$certDir\temp.pfx" -Password $certPassword | Out-Null
            
            # Convert to PEM format using certutil
            certutil -encode "$certDir\temp.pfx" "$certDir\temp.pem" | Out-Null
            
            # Extract certificate and key (this is a simplified approach)
            Write-ColorOutput "Note: PowerShell certificate generation has limitations." -Color Yellow
            Write-ColorOutput "For production, use OpenSSL or enterprise CA certificates." -Color Yellow
            
            # Move certificate to trusted root
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
            $store.Open("ReadWrite")
            $store.Add($cert)
            $store.Close()
            
            # Clean up temp files
            Remove-Item "$certDir\temp.pfx" -Force -ErrorAction SilentlyContinue
            Remove-Item "$certDir\temp.pem" -Force -ErrorAction SilentlyContinue
            
            Write-ColorOutput "✓ Certificate generated and trusted (using PowerShell method)" -Color Green
            Write-ColorOutput "⚠ For better compatibility, install OpenSSL and regenerate" -Color Yellow
        }
        
        Write-ColorOutput "  Certificate: $certPath" -Color Default
        Write-ColorOutput "  Private Key: $keyPath" -Color Default
        Write-ColorOutput ""
        
        # Trust the new certificate
        if ($Script:OpenSSLPath) {
            Write-ColorOutput "Adding certificate to Windows Certificate Store..." -Color Default
            $certutil = certutil -addstore -f "Root" $certPath 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-ColorOutput "✓ Certificate trusted!" -Color Green
            } else {
                Write-ColorOutput "✗ Failed to trust certificate: $certutil" -Color Red
            }
        }
    }
    
    # 4. Show certificate details
    if ((Test-Path $certPath) -and $Script:OpenSSLPath) {
        Write-ColorOutput ""
        Write-ColorOutput "Certificate domains (SAN):" -Color Default
        $sanInfo = & $Script:OpenSSLPath x509 -in $certPath -text -noout 2>$null | Select-String "DNS:"
        if ($sanInfo) {
            $sanInfo | ForEach-Object { Write-ColorOutput "  $_" -Color Default }
        }
    }
}

function Start-Setup {
    Write-ColorOutput "Postman Auth Router Setup" -Color Green
    Write-ColorOutput "==================================" -Color Default
    Write-ColorOutput ""
    
    # Check dependencies first
    Write-ColorOutput "Checking dependencies..." -Color Default
    if (-not (Test-Dependencies)) {
        Write-ColorOutput "✗ Missing dependencies. Please install them first." -Color Red
        exit 1
    }
    Write-ColorOutput ""
    
    # Explain what will happen
    Write-ColorOutput "This will configure your system for Postman SAML authentication:" -Color Default
    Write-ColorOutput "  1. Add entries to hosts file (with markers for safe removal)" -Color Default
    Write-ColorOutput "  2. Generate/trust SSL certificates" -Color Default
    Write-ColorOutput "  3. Configure from template (if needed)" -Color Default
    Write-ColorOutput "  4. Start the authentication daemon" -Color Default
    Write-ColorOutput "  5. Add firewall rule for port 443" -Color Default
    Write-ColorOutput ""
    
    # Get confirmation
    $response = Read-Host "Continue with setup? (y/N)"
    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-ColorOutput "Setup cancelled." -Color Yellow
        exit 0
    }
    Write-ColorOutput ""
    
    # 1. Setup hosts file with markers
    Write-ColorOutput "Configuring hosts file..." -Color Default
    $hostsContent = Get-Content $Script:Config.HostsFile -Raw
    
    if (-not ($hostsContent -match $START_MARKER)) {
        Write-ColorOutput "Adding hosts entries..." -Color Yellow
        
        # Backup hosts file
        $backupPath = "$($Script:Config.HostsFile).backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item $Script:Config.HostsFile $backupPath
        
        # Add marked section
        $newEntries = @"

$START_MARKER
127.0.0.1 identity.getpostman.com
127.0.0.1 identity.postman.co
$END_MARKER
"@
        Add-Content -Path $Script:Config.HostsFile -Value $newEntries
        Write-ColorOutput "  ✓ Hosts entries added (backup created at $backupPath)" -Color Green
    } else {
        Write-ColorOutput "  ✓ Hosts entries already configured" -Color Green
    }
    
    # 2. Handle certificates
    Write-ColorOutput ""
    Manage-Certificates
    
    # 3. Setup config from template if needed
    Write-ColorOutput ""
    Write-ColorOutput "Checking configuration..." -Color Default
    $configPath = Join-Path (Get-Location) "config\config.json"
    $templatePath = Join-Path (Get-Location) "config\config.json.template"
    
    if (-not (Test-Path $configPath)) {
        if (Test-Path $templatePath) {
            Write-ColorOutput "Creating config from template..." -Color Default
            Copy-Item $templatePath $configPath
            Write-ColorOutput "⚠ Please edit config\config.json with your IDP settings" -Color Yellow
            Write-ColorOutput "  Required: postman_team_name, okta_tenant_id (or equivalent)" -Color Default
            Write-ColorOutput ""
            Read-Host "Press Enter to continue after editing config..."
        } else {
            Write-ColorOutput "✗ Config template not found" -Color Red
            exit 1
        }
    } else {
        Write-ColorOutput "  ✓ Config file exists" -Color Green
    }
    
    # 4. Add firewall rule
    Write-ColorOutput ""
    Write-ColorOutput "Configuring Windows Firewall..." -Color Default
    $ruleName = "Postman Auth Router"
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    
    if (-not $existingRule) {
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 443 `
            -Action Allow `
            -Profile Any | Out-Null
        Write-ColorOutput "  ✓ Firewall rule added for port 443" -Color Green
    } else {
        Write-ColorOutput "  ✓ Firewall rule already exists" -Color Green
    }
    
    # 5. Start daemon
    Write-ColorOutput ""
    Start-Daemon
    
    # 6. Run preflight checks
    Write-ColorOutput ""
    Write-ColorOutput "Running preflight checks..." -Color Default
    Start-Sleep -Seconds 2
    Start-Preflight
    Write-ColorOutput ""
    Write-ColorOutput "Setup complete! To remove everything: .\daemon_manager.ps1 cleanup" -Color Green
}

function Start-Preflight {
    Write-ColorOutput "Running preflight checks..." -Color Green
    Write-ColorOutput "Validating configuration before manual testing" -Color Default
    Write-ColorOutput ""
    
    $errors = 0
    $warnings = 0
    
    # 1. Check hosts file entries
    Write-ColorOutput "Checking hosts file configuration..." -Color Default
    $hostsContent = Get-Content $Script:Config.HostsFile
    
    @("identity.getpostman.com", "identity.postman.co") | ForEach-Object {
        if ($hostsContent -match "127\.0\.0\.1\s+$_") {
            Write-ColorOutput "  ✓ $_ redirected to localhost" -Color Green
        } else {
            Write-ColorOutput "  ✗ $_ NOT in hosts file" -Color Red
            $errors++
        }
    }
    
    # 2. Check certificate exists and is trusted
    Write-ColorOutput ""
    Write-ColorOutput "Checking certificate configuration..." -Color Default
    $certPath = Join-Path (Get-Location) $Script:Config.CertFile
    
    if (Test-Path $certPath) {
        Write-ColorOutput "  ✓ Certificate exists" -Color Green
        
        # Check if trusted
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
            $store.Open("ReadOnly")
            $trusted = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
            $store.Close()
            
            if ($trusted) {
                Write-ColorOutput "  ✓ Certificate is in Windows Certificate Store" -Color Green
            } else {
                Write-ColorOutput "  ✗ Certificate not in Certificate Store" -Color Red
                $errors++
            }
        } catch {
            Write-ColorOutput "  ✗ Could not validate certificate" -Color Red
            $errors++
        }
    } else {
        Write-ColorOutput "  ✗ Certificate not found" -Color Red
        $errors++
    }
    
    # 3. Check daemon is running
    Write-ColorOutput ""
    Write-ColorOutput "Checking daemon status..." -Color Default
    
    $running = $false
    if (Test-Path $Script:Config.PidFile) {
        $pid = Get-Content $Script:Config.PidFile -ErrorAction SilentlyContinue
        if ($pid) {
            $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($process) {
                $running = $true
                Write-ColorOutput "  ✓ Daemon is running (PID: $pid)" -Color Green
            }
        }
    }
    
    if (-not $running) {
        Write-ColorOutput "  ✗ Daemon is not running" -Color Red
        $errors++
    } else {
        # Check health endpoint
        try {
            $response = Invoke-WebRequest -Uri "https://identity.getpostman.com/health" -UseBasicParsing -SkipCertificateCheck -TimeoutSec 5
            if ($response.Content -match "healthy") {
                Write-ColorOutput "  ✓ Health endpoint responding" -Color Green
            } else {
                Write-ColorOutput "  ⚠ Health endpoint not responding correctly" -Color Yellow
                $warnings++
            }
        } catch {
            Write-ColorOutput "  ⚠ Could not reach health endpoint" -Color Yellow
            $warnings++
        }
    }
    
    # 4. Check config exists
    Write-ColorOutput ""
    Write-ColorOutput "Checking configuration..." -Color Default
    $configPath = Join-Path (Get-Location) "config\config.json"
    
    if (Test-Path $configPath) {
        Write-ColorOutput "  ✓ Config file exists" -Color Green
        
        # Check if it's not just the template
        $templatePath = Join-Path (Get-Location) "config\config.json.template"
        if ((Test-Path $templatePath) -and ((Get-FileHash $configPath).Hash -eq (Get-FileHash $templatePath).Hash)) {
            Write-ColorOutput "  ⚠ Config appears to be unmodified template" -Color Yellow
            $warnings++
        } else {
            Write-ColorOutput "  ✓ Config has been customized" -Color Green
        }
    } else {
        Write-ColorOutput "  ✗ Config file not found" -Color Red
        $errors++
    }
    
    # 5. Check DNS resolution
    Write-ColorOutput ""
    Write-ColorOutput "Checking DNS configuration..." -Color Default
    try {
        $result = Resolve-DnsName -Name "identity.getpostman.com" -Server "8.8.8.8" -ErrorAction Stop
        if ($result) {
            Write-ColorOutput "  ✓ External DNS resolution working" -Color Green
        }
    } catch {
        Write-ColorOutput "  ⚠ Could not verify external DNS" -Color Yellow
        $warnings++
    }
    
    # Summary
    Write-ColorOutput ""
    Write-ColorOutput "======================================" -Color Default
    if ($errors -eq 0) {
        if ($warnings -eq 0) {
            Write-ColorOutput "✅ All preflight checks passed!" -Color Green
        } else {
            Write-ColorOutput "✅ Preflight passed with $warnings warnings" -Color Green
        }
        Write-ColorOutput ""
        Write-ColorOutput "Ready for manual testing:" -Color Default
        Write-ColorOutput "  - Browser: https://postman.co" -Color Default
        Write-ColorOutput "  - Desktop: Open Postman Desktop app" -Color Default
    } else {
        Write-ColorOutput "❌ Preflight failed with $errors errors, $warnings warnings" -Color Red
        Write-ColorOutput ""
        Write-ColorOutput "Fix errors before testing. Run: .\daemon_manager.ps1 setup" -Color Default
    }
    Write-ColorOutput "======================================" -Color Default
}

function Start-Cleanup {
    Write-ColorOutput "Cleaning up demo environment..." -Color Green
    Write-ColorOutput "This will remove all traces of the Postman Auth Router" -Color Default
    Write-ColorOutput ""
    
    # 1. Stop daemon
    Write-ColorOutput "Stopping daemon..." -Color Default
    Stop-Daemon
    
    # 2. Remove hosts entries (using markers for safety)
    Write-ColorOutput ""
    Write-ColorOutput "Removing hosts entries..." -Color Default
    $hostsContent = Get-Content $Script:Config.HostsFile -Raw
    
    if ($hostsContent -match $START_MARKER) {
        # Create backup
        $backupPath = "$($Script:Config.HostsFile).backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item $Script:Config.HostsFile $backupPath
        
        # Remove marked section
        $pattern = "(?ms)$([regex]::Escape($START_MARKER)).*?$([regex]::Escape($END_MARKER))\r?\n?"
        $newContent = $hostsContent -replace $pattern, ""
        Set-Content -Path $Script:Config.HostsFile -Value $newContent -NoNewline
        Write-ColorOutput "  ✓ Hosts entries removed (backup at $backupPath)" -Color Green
    } else {
        Write-ColorOutput "  ⚠ No marked hosts entries found" -Color Yellow
    }
    
    # 3. Remove certificate from store
    Write-ColorOutput ""
    Write-ColorOutput "Removing certificate from Windows Certificate Store..." -Color Default
    $certPath = Join-Path (Get-Location) $Script:Config.CertFile
    
    if (Test-Path $certPath) {
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
            $store.Open("ReadWrite")
            $toRemove = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
            if ($toRemove) {
                $store.Remove($toRemove)
                Write-ColorOutput "  ✓ Certificate removed from store" -Color Green
            } else {
                Write-ColorOutput "  ⚠ Certificate not found in store" -Color Yellow
            }
            $store.Close()
        } catch {
            Write-ColorOutput "  ⚠ Could not remove certificate: $_" -Color Yellow
        }
    }
    
    # 4. Remove generated files
    Write-ColorOutput ""
    Write-ColorOutput "Removing generated files..." -Color Default
    $certDir = Join-Path (Get-Location) $Script:Config.CertDir
    
    @("cert.pem", "key.pem", "*.crt", "*.key", "*.csr", "*.pfx") | ForEach-Object {
        $files = Get-ChildItem -Path $certDir -Filter $_ -ErrorAction SilentlyContinue
        if ($files) {
            $files | Remove-Item -Force
            Write-ColorOutput "  ✓ Removed $_" -Color Green
        }
    }
    
    # 5. Optionally remove config
    $configPath = Join-Path (Get-Location) "config\config.json"
    if (Test-Path $configPath) {
        $response = Read-Host "Remove config\config.json? (y/N)"
        if ($response -eq 'y' -or $response -eq 'Y') {
            Remove-Item $configPath -Force
            Write-ColorOutput "  ✓ Config removed" -Color Green
        } else {
            Write-ColorOutput "  ⚠ Config kept" -Color Yellow
        }
    }
    
    # 6. Remove firewall rule
    Write-ColorOutput ""
    Write-ColorOutput "Removing firewall rule..." -Color Default
    $ruleName = "Postman Auth Router"
    $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($rule) {
        Remove-NetFirewallRule -DisplayName $ruleName
        Write-ColorOutput "  ✓ Firewall rule removed" -Color Green
    } else {
        Write-ColorOutput "  ⚠ Firewall rule not found" -Color Yellow
    }
    
    # 7. Clear DNS cache
    Write-ColorOutput ""
    Write-ColorOutput "Flushing DNS cache..." -Color Default
    ipconfig /flushdns | Out-Null
    Write-ColorOutput "  ✓ DNS cache flushed" -Color Green
    
    # 8. Clean up ProgramData folder
    if (Test-Path $Script:Config.InstallDir) {
        Remove-Item $Script:Config.InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $Script:Config.LogDir) {
        Remove-Item $Script:Config.LogDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    Write-ColorOutput ""
    Write-ColorOutput "======================================" -Color Default
    Write-ColorOutput "✅ Cleanup complete!" -Color Green
    Write-ColorOutput ""
    Write-ColorOutput "The system has been restored to its original state." -Color Default
    Write-ColorOutput "To set up again, run: .\daemon_manager.ps1 setup" -Color Default
    Write-ColorOutput "======================================" -Color Default
}

function Show-Help {
    Write-ColorOutput ""
    Write-ColorOutput "Postman Auth Router - Enterprise SAML Enforcement" -Color Blue
    Write-ColorOutput "==================================================" -Color Default
    Write-ColorOutput ""
    Write-ColorOutput "Usage: .\daemon_manager.ps1 <command>" -Color Default
    Write-ColorOutput ""
    Write-ColorOutput "Quick Start:" -Color Blue
    Write-ColorOutput "  setup        Complete setup with all configurations" -Color Default
    Write-ColorOutput "  cleanup      Remove all changes and restore system" -Color Default
    Write-ColorOutput ""
    Write-ColorOutput "Service Management:" -Color Blue
    Write-ColorOutput "  start        Start the authentication daemon" -Color Default
    Write-ColorOutput "  stop         Stop the daemon" -Color Default
    Write-ColorOutput "  restart      Restart the daemon" -Color Default
    Write-ColorOutput "  status       Check daemon status and health" -Color Default
    Write-ColorOutput "  logs         View daemon logs (real-time)" -Color Default
    Write-ColorOutput ""
    Write-ColorOutput "Certificate Management:" -Color Blue
    Write-ColorOutput "  cert         Smart certificate management (generate/trust as needed)" -Color Default
    Write-ColorOutput ""
    Write-ColorOutput "Validation:" -Color Blue
    Write-ColorOutput "  preflight    Run preflight checks before manual testing" -Color Default
    Write-ColorOutput ""
    Write-ColorOutput "Examples:" -Color Blue
    Write-ColorOutput "  .\daemon_manager.ps1 setup       # First time setup" -Color Default
    Write-ColorOutput "  .\daemon_manager.ps1 preflight   # Validate configuration" -Color Default
    Write-ColorOutput "  .\daemon_manager.ps1 cleanup     # Complete removal" -Color Default
    Write-ColorOutput ""
    Write-ColorOutput "Testing After Setup:" -Color Blue
    Write-ColorOutput "  Browser:  https://postman.co" -Color Default
    Write-ColorOutput "  Desktop:  Open Postman Desktop app" -Color Default
    Write-ColorOutput ""
    if (-not (Test-Administrator)) {
        Write-ColorOutput "Note: Run as Administrator for all commands" -Color Yellow
    }
}

# Main execution
if ($Command -ne "help" -and -not (Test-Administrator)) {
    Write-ColorOutput "Please run as Administrator:" -Color Red
    Write-ColorOutput "Right-click PowerShell and select 'Run as Administrator'" -Color Yellow
    exit 1
}

switch ($Command.ToLower()) {
    "start" { Start-Daemon }
    "stop" { Stop-Daemon }
    "restart" { 
        Stop-Daemon
        Start-Sleep -Seconds 2
        Start-Daemon
    }
    "status" { Get-DaemonStatus }
    "logs" { Show-Logs }
    { $_ -in "cert", "certificate", "certs" } { Manage-Certificates }
    { $_ -in "generate-cert", "trust-cert" } { Manage-Certificates }  # Backward compatibility
    "setup" { Start-Setup }
    "demo" { Start-Setup }  # Backward compatibility
    "preflight" { Start-Preflight }
    "cleanup" { Start-Cleanup }
    default { Show-Help }
}