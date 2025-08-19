# Postman SAML Daemon Manager for Windows
param([string]$Command = "help")

# Check admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run as Administrator"
    exit 1
}

# Configuration
$HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$PidFile = "$env:TEMP\postman-daemon.pid"

# Hosts management
function Add-Hosts {
    $hostsContent = Get-Content $HostsFile -Raw
    if (-not ($hostsContent -match "127\.0\.0\.1\s+identity\.getpostman\.com")) {
        Copy-Item $HostsFile "$HostsFile.backup"
        Add-Content $HostsFile "`n127.0.0.1 identity.getpostman.com"
        Write-Host "Added hosts entry"
    }
}

function Remove-Hosts {
    $hostsContent = Get-Content $HostsFile
    $filtered = $hostsContent | Where-Object { $_ -notmatch "127\.0\.0\.1\s+identity\.getpostman\.com" }
    if ($hostsContent.Count -ne $filtered.Count) {
        Copy-Item $HostsFile "$HostsFile.backup"
        Set-Content $HostsFile $filtered
        Write-Host "Removed hosts entry"
    }
}

# Find Python
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $python) {
    Write-Host "Python not found"
    exit 1
}

switch ($Command.ToLower()) {
    "start" {
        Write-Host "Starting daemon..."
        Add-Hosts
        
        # Kill existing
        Get-Process -Name python* -ErrorAction SilentlyContinue | 
            Where-Object { $_.CommandLine -like "*saml_enforcer*" } | 
            Stop-Process -Force
        
        # Free port 443
        $port443 = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
        if ($port443) {
            Stop-Process -Id $port443.OwningProcess -Force -ErrorAction SilentlyContinue
        }
        
        Start-Sleep 1
        
        # Start daemon
        $process = Start-Process -FilePath $python.Source -ArgumentList "src\saml_enforcer.py" -WindowStyle Hidden -PassThru
        $process.Id | Out-File $PidFile
        
        Start-Sleep 2
        if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
            Write-Host "Started"
        } else {
            Write-Host "Failed to start"
            Remove-Hosts
            exit 1
        }
    }
    
    "stop" {
        Write-Host "Stopping daemon..."
        
        # Try PID file first
        if (Test-Path $PidFile) {
            $pid = Get-Content $PidFile -ErrorAction SilentlyContinue
            if ($pid) {
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            }
            Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
        }
        
        # Fallback
        Get-Process -Name python* -ErrorAction SilentlyContinue | 
            Where-Object { $_.CommandLine -like "*saml_enforcer*" } | 
            Stop-Process -Force
        
        Remove-Hosts
        Write-Host "Stopped"
    }
    
    "restart" {
        & $PSCommandPath stop
        Start-Sleep 1
        & $PSCommandPath start
    }
    
    "status" {
        $running = $false
        
        if (Test-Path $PidFile) {
            $pid = Get-Content $PidFile -ErrorAction SilentlyContinue
            if ($pid -and (Get-Process -Id $pid -ErrorAction SilentlyContinue)) {
                $running = $true
            }
        }
        
        if ($running) {
            Write-Host "Running"
        } else {
            Write-Host "Not running"
        }
    }
    
    default {
        Write-Host "Usage: .\daemon_manager.ps1 {start|stop|restart|status}"
        exit 1
    }
}