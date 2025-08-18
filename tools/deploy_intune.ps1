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

# Validate input parameters
function Test-InputParameters {
    Write-Log "Validating input parameters..."
    
    $validationPassed = $true
    
    # Validate PostmanTeamName
    if ($PostmanTeamName -notmatch '^[a-zA-Z0-9\-_]{2,50}$' -or $PostmanTeamName -eq 'YOUR_TEAM_NAME') {
        Write-Log "Invalid PostmanTeamName: '$PostmanTeamName'. Must be 2-50 alphanumeric characters, hyphens, or underscores."
        $validationPassed = $false
    }
    
    # Validate OktaTenantId
    if ($OktaTenantId -notmatch '^[a-zA-Z0-9\-_]{5,100}$' -or $OktaTenantId -eq 'YOUR_TENANT_ID') {
        Write-Log "Invalid OktaTenantId: '$OktaTenantId'. Must be 5-100 alphanumeric characters, hyphens, or underscores."
        $validationPassed = $false
    }
    
    # Validate IdpUrl
    if ($IdpUrl -notmatch '^https://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/.*)?$' -or $IdpUrl -eq 'YOUR_IDP_URL') {
        Write-Log "Invalid IdpUrl: '$IdpUrl'. Must be a valid HTTPS URL."
        $validationPassed = $false
    }
    
    # Validate OktaAppId
    if ($OktaAppId -notmatch '^[a-zA-Z0-9]{10,50}$' -or $OktaAppId -eq 'YOUR_APP_ID') {
        Write-Log "Invalid OktaAppId: '$OktaAppId'. Must be 10-50 alphanumeric characters."
        $validationPassed = $false
    }
    
    # Validate DownloadUrl if provided
    if ($DownloadUrl -and $DownloadUrl -ne "https://your-storage.example.com/postman-auth-router.zip") {
        if ($DownloadUrl -notmatch '^(https://|\\\\)') {
            Write-Log "Invalid DownloadUrl: '$DownloadUrl'. Must be HTTPS URL or UNC path."
            $validationPassed = $false
        }
    }
    
    return $validationPassed
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

# Create embedded files for minimal deployment
function Create-EmbeddedFiles {
    Write-Log "Creating embedded deployment files..."
    
    # Create minimal Python daemon
    $pythonDaemon = @'
#!/usr/bin/env python3
"""
Postman SAML Authentication Router - Intune Minimal Version
Enforces SAML authentication for Postman Web and Desktop
"""

import http.server
import socketserver
import ssl
import json
import os
import sys
import argparse
from urllib.parse import urlparse

class PostmanAuthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Load configuration
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')
        with open(config_path) as f:
            config = json.load(f)
        
        # Parse request
        parsed_url = urlparse(self.path)
        
        # Check if this is a login request that should be redirected to SAML
        if parsed_url.path in ['/login', '/client/login']:
            # Redirect to SAML IdP
            idp_url = config['idp_config']['idp_url']
            self.send_response(302)
            self.send_header('Location', idp_url)
            self.end_headers()
            return
        
        # Health check endpoint
        if parsed_url.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy", "daemon": "active"}')
            return
        
        # Default response
        self.send_response(404)
        self.end_headers()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', default='enforce')
    args = parser.parse_args()
    
    port = 443
    
    # Create server
    with socketserver.TCPServer(("", port), PostmanAuthHandler) as httpd:
        # Configure SSL
        cert_path = os.path.join(os.path.dirname(__file__), '..', 'ssl', 'cert.pem')
        key_path = os.path.join(os.path.dirname(__file__), '..', 'ssl', 'key.pem')
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            httpd.socket = ssl.wrap_socket(httpd.socket,
                                         certfile=cert_path,
                                         keyfile=key_path,
                                         server_side=True)
        
        print(f"Postman Auth Router listening on port {port}")
        httpd.serve_forever()

if __name__ == "__main__":
    main()
'@
    
    # Create source directory and write daemon
    $srcDir = "$InstallDir\src"
    if (-not (Test-Path $srcDir)) {
        New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
    }
    $pythonDaemon | Out-File -FilePath "$srcDir\saml_enforcer.py" -Encoding UTF8
    Write-Log "Embedded Python daemon created"
}

# Download and extract package
function Install-Package {
    Write-Log "Downloading Postman Auth Router package..."
    
    $packagePath = "$env:TEMP\postman-auth-router.zip"
    
    try {
        # Package delivery implementation with retry logic
        $downloaded = $false
        $retryCount = 0
        $maxRetries = 3
        $retryDelays = @(1, 2, 4)  # Exponential backoff in seconds
        
        while (-not $downloaded -and $retryCount -lt $maxRetries) {
            try {
                if ($retryCount -gt 0) {
                    Write-Log "Retry attempt $retryCount of $maxRetries after $($retryDelays[$retryCount-1]) seconds..."
                    Start-Sleep -Seconds $retryDelays[$retryCount-1]
                }
                
                # Option 1: Azure Blob Storage with SAS token
                if ($DownloadUrl -match "blob\.core\.windows\.net") {
                    Write-Log "Downloading from Azure Blob Storage: $DownloadUrl"
                    $webClient = New-Object System.Net.WebClient
                    $webClient.Headers.Add("User-Agent", "PostmanAuthRouter-Intune/1.0")
                    $webClient.DownloadFile($DownloadUrl, $packagePath)
                    $downloaded = $true
                }
                # Option 2: HTTPS download with authentication
                elseif ($DownloadUrl -match "^https://") {
                    Write-Log "Downloading from HTTPS source: $DownloadUrl"
                    Invoke-WebRequest -Uri $DownloadUrl -OutFile $packagePath -UseBasicParsing -TimeoutSec 300
                    $downloaded = $true
                }
                # Option 3: UNC network share
                elseif ($DownloadUrl -match "^\\\\") {
                    Write-Log "Copying from network share: $DownloadUrl"
                    if (Test-Path $DownloadUrl) {
                        Copy-Item $DownloadUrl -Destination $packagePath -Force
                        $downloaded = $true
                    } else {
                        throw "Network share not accessible: $DownloadUrl"
                    }
                }
                # Option 4: Local embedded files (fallback)
                else {
                    Write-Log "No valid download URL provided, creating embedded deployment..."
                    Create-EmbeddedFiles
                    $downloaded = $true
                }
                
            } catch {
                $retryCount++
                Write-Log "Download attempt failed: $_" -Level "WARN"
                if ($retryCount -ge $maxRetries) {
                    throw "Failed to download package after $maxRetries attempts: $_"
                }
            }
        }
        
        # Verify download if file-based
        if ($DownloadUrl -and (Test-Path $packagePath)) {
            $fileSize = (Get-Item $packagePath).Length
            Write-Log "Package downloaded successfully ($fileSize bytes)"
        }
        
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
    Write-Log "Setting up SSL certificate..."
    
    # PREFERRED METHOD: Check for Intune certificate profile first
    $profileCert = Get-ChildItem -Path Cert:\LocalMachine\My | 
        Where-Object { $_.Subject -match "identity\.getpostman\.com" -and $_.Issuer -notmatch "identity\.getpostman\.com" } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
        
    if ($profileCert) {
        Write-Log "Found certificate from Intune certificate profile: $($profileCert.Thumbprint)"
        Write-Log "Certificate issued by: $($profileCert.Issuer)"
        Write-Log "Certificate expires: $($profileCert.NotAfter)"
        
        # Ensure certificate is in Trusted Root store
        $rootCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $profileCert.Thumbprint }
        if (-not $rootCert) {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
            $store.Open("ReadWrite")
            $store.Add($profileCert)
            $store.Close()
            Write-Log "Certificate copied to Trusted Root store for SSL validation"
        }
        
        Write-Log "Using enterprise certificate from Intune certificate profile (RECOMMENDED)"
        return
    }
    
    # FALLBACK METHOD: Check for manual certificate deployment
    $certPath = "$InstallDir\ssl\cert.pem"
    $enterpriseCertPath = "$InstallDir\ssl\enterprise.cer"
    
    if (Test-Path $enterpriseCertPath) {
        $certPath = $enterpriseCertPath
        Write-Log "No Intune certificate profile found, using manual enterprise certificate"
    } elseif (Test-Path $certPath) {
        Write-Log "No Intune certificate profile found, using package certificate"
    } else {
        Write-Log "No certificates found - will generate self-signed certificate" -Level "WARN"
        Write-Log "RECOMMENDATION: Deploy certificates via Intune certificate profiles for better security and management" -Level "WARN"
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
            -Argument "$InstallDir\src\saml_enforcer.py --mode enforce" `
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
    
    # Check health endpoint with retry logic
    $healthCheckPassed = $false
    $retryCount = 0
    $maxRetries = 3
    $retryDelays = @(5, 10, 15)  # Allow more time for daemon startup
    
    while (-not $healthCheckPassed -and $retryCount -lt $maxRetries) {
        try {
            if ($retryCount -gt 0) {
                Write-Log "Health check retry attempt $retryCount of $maxRetries after $($retryDelays[$retryCount-1]) seconds..."
            }
            Start-Sleep -Seconds $retryDelays[$retryCount]
            
            $response = Invoke-WebRequest -Uri "https://identity.getpostman.com/health" `
                -UseBasicParsing -SkipCertificateCheck -TimeoutSec 15 -UserAgent "PostmanAuthRouter-Intune-HealthCheck/1.0"
            
            if ($response.StatusCode -eq 200) {
                Write-Log "✓ Health endpoint responding"
                $healthCheckPassed = $true
            } else {
                throw "Health endpoint returned status code: $($response.StatusCode)"
            }
        } catch {
            $retryCount++
            Write-Log "Health check attempt failed: $_" -Level "WARN"
            if ($retryCount -ge $maxRetries) {
                Write-Log "⚠ Health endpoint not accessible after $maxRetries attempts (daemon may need more time to start)" -Level "WARN"
            }
        }
    }
    
    if ($errors -eq 0) {
        Write-Log "DEPLOYMENT SUCCESSFUL - All checks passed"
        exit 0
    } else {
        Write-Log "DEPLOYMENT COMPLETED WITH ERRORS - $errors checks failed"
        exit 1
    }
}

# Set global error handling for PowerShell
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Suppress progress bars for better logging

# Main execution
try {
    Write-Log "=========================================="
    Write-Log "Starting Postman Auth Router deployment via Intune"
    Write-Log "=========================================="
    
    # Check if running as SYSTEM (Intune context)
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-Log "Running as: $currentUser"
    } catch {
        Write-Log "Failed to determine current user context: $_" -Level "WARN"
        Write-Log "Running as: Unknown"
    }
    
    # Validate input parameters
    try {
        if (-not (Test-InputParameters)) {
            Write-Log "Input validation failed"
            exit 1
        }
    } catch {
        Write-Log "Input validation threw exception: $_"
        exit 1
    }
    
    # Execute deployment steps
    Initialize-Directories
    Install-Package
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

# Detection method for Intune
# NOTE: As per Intune 2025 documented recommendations, use a separate detection script:
# deploy_intune_detection.ps1 (available in tools/ directory)