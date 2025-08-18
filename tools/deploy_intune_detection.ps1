#############################################################################
# Postman SAML Authentication Router - Intune Detection Script
# 
# This script detects whether the Postman authentication daemon is properly
# installed and configured. Deploy separately as detection script in Intune.
#
# Version: 1.0
# Date: 2025-08-17
#############################################################################

# Detection logic for Intune compliance
$installed = $true
$reasons = @()

# Check if daemon is installed
$daemonPath = "$env:ProgramData\Postman\AuthRouter\src\auth_router_final.py"
if (-not (Test-Path $daemonPath)) {
    $installed = $false
    $reasons += "Auth router not installed at $daemonPath"
}

# Check if scheduled task exists and is running
$task = Get-ScheduledTask -TaskName "PostmanAuthRouter" -ErrorAction SilentlyContinue
if (-not $task) {
    $installed = $false
    $reasons += "Scheduled task 'PostmanAuthRouter' not found"
} elseif ($task.State -ne "Running") {
    $installed = $false
    $reasons += "Daemon not running (State: $($task.State))"
}

# Check hosts file configuration
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsFile) {
    $hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
    if ($hostsContent -notmatch "127\.0\.0\.1\s+identity\.getpostman\.com") {
        $installed = $false
        $reasons += "Hosts file not configured for identity.getpostman.com"
    }
} else {
    $installed = $false
    $reasons += "Hosts file not found"
}

# Check certificate installation
$cert = Get-ChildItem -Path Cert:\LocalMachine\Root | 
    Where-Object { $_.Subject -match "identity\.getpostman\.com" }
if (-not $cert) {
    $installed = $false
    $reasons += "SSL certificate not found in Trusted Root store"
}

# Check configuration file
$configPath = "$env:ProgramData\Postman\AuthRouter\config\config.json"
if (-not (Test-Path $configPath)) {
    $installed = $false
    $reasons += "Configuration file not found at $configPath"
} else {
    try {
        $config = Get-Content $configPath | ConvertFrom-Json
        if (-not $config.postman_team_name -or $config.postman_team_name -eq "YOUR_TEAM_NAME") {
            $installed = $false
            $reasons += "Configuration not properly set (team name not configured)"
        }
    } catch {
        $installed = $false
        $reasons += "Configuration file corrupted or invalid JSON"
    }
}

# Optional: Test health endpoint if daemon should be running
if ($installed) {
    try {
        $healthResponse = Invoke-WebRequest -Uri "https://identity.getpostman.com/health" `
            -UseBasicParsing -SkipCertificateCheck -TimeoutSec 5 -ErrorAction Stop
        if ($healthResponse.StatusCode -ne 200) {
            $installed = $false
            $reasons += "Health endpoint returned status $($healthResponse.StatusCode)"
        }
    } catch {
        # Don't fail detection if health check fails - daemon might be starting
        # This is informational only
        Write-Host "INFO: Health endpoint not accessible - daemon may be starting"
    }
}

# Output results for Intune
if ($installed) {
    Write-Host "Postman Auth Router is installed and configured"
    exit 0
} else {
    Write-Host "Not installed: $($reasons -join '; ')"
    exit 1
}