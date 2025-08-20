# Postman SAML Enforcer Windows Service Installer
# Requires Administrator privileges

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("install", "uninstall", "start", "stop", "status", "srefresh")]
    [string]$Action,
    
    [string]$ServicePath = "C:\Program Files\Postman SAML Enforcer"
)

# Auto-detect project structure
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)

# Validate project structure
if (-not (Test-Path "$ProjectRoot\src\saml_enforcer.py")) {
    Write-Host "Error: Could not locate project structure from script location"
    Write-Host "Expected to find: $ProjectRoot\src\saml_enforcer.py"
    exit 1
}

# Check for Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Administrator privileges required. Please run PowerShell as Administrator."
    exit 1
}

$ServiceName = "PostmanSAMLEnforcer"
$ServiceDisplayName = "Postman SAML Enforcer"
$ServiceDescription = "Enterprise SAML enforcement daemon for Postman Desktop applications"

$ServiceWrapperScript = "$ServicePath\service\windows\service_wrapper.py"
$PythonScript = "$ServicePath\src\saml_enforcer.py"
$LocalPythonScript = "$ProjectRoot\src\saml_enforcer.py"

function Install-Python {
    Write-Host "Python not found. Installing Python..."
    
    try {
        # Use winget (modern Windows package manager)
        & winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Python installed successfully"
            # Refresh PATH
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            return "python"
        } else {
            throw "winget installation failed"
        }
    } catch {
        Write-Host "winget not available, downloading Python directly..."
        
        try {
            # Download Python installer
            $pythonUrl = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
            $installerPath = "$env:TEMP\python-installer.exe"
            
            Write-Host "Downloading Python installer..."
            Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath
            
            Write-Host "Installing Python (this may take a few minutes)..."
            & $installerPath /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
            
            # Wait for installation to complete
            Start-Sleep -Seconds 30
            
            # Clean up
            Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
            
            # Refresh PATH
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            
            Write-Host "Python installation completed"
            return "python"
            
        } catch {
            Write-Host "Failed to install Python automatically: $_"
            Write-Host "Please install Python3 manually from https://www.python.org/"
            exit 1
        }
    }
}

function Get-PythonExecutable {
    # Try common Python executable names
    $pythonCommands = @("python3", "python", "py")
    
    foreach ($cmd in $pythonCommands) {
        try {
            $result = & $cmd --version 2>$null
            if ($LASTEXITCODE -eq 0) {
                return (Get-Command $cmd).Source
            }
        } catch {
            continue
        }
    }
    
    # Python not found - auto-install
    Install-Python
    
    # Try again after installation
    foreach ($cmd in $pythonCommands) {
        try {
            $result = & $cmd --version 2>$null
            if ($LASTEXITCODE -eq 0) {
                return (Get-Command $cmd).Source
            }
        } catch {
            continue
        }
    }
    
    throw "Python installation failed or Python still not accessible after installation."
}

function Install-PostmanService {
    Write-Host "Installing Postman SAML Enforcer service..."
    
    # Get Python executable (auto-installs if needed)
    $PythonExe = Get-PythonExecutable
    
    # Copy entire project to service installation directory
    Write-Host "Copying project files to $ServicePath..."
    if (Test-Path $ServicePath) {
        Remove-Item $ServicePath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $ServicePath -Force | Out-Null
    Copy-Item -Path "$ProjectRoot\*" -Destination $ServicePath -Recurse -Force
    
    $ServiceExecutable = "`"$PythonExe`" `"$ServiceWrapperScript`""
    
    # Check if service already exists
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Host "Service already exists. Stopping and removing..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName
        Start-Sleep -Seconds 2
    }
    
    # Create service using sc.exe for better control
    $arguments = @(
        "create"
        $ServiceName
        "binPath=`"$ServiceExecutable`""
        "DisplayName=`"$ServiceDisplayName`""
        "start=auto"
        "type=own"
        "error=normal"
    )
    
    $result = & sc.exe @arguments
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Service created successfully"
        
        # Set service description
        & sc.exe description $ServiceName $ServiceDescription
        
        # Configure service recovery options
        & sc.exe failure $ServiceName reset=0 actions=restart/5000/restart/10000/restart/15000
        
        # Set service to restart on failure
        & sc.exe failureflag $ServiceName 1
        
        Write-Host "Service configured for automatic restart on failure"
    } else {
        Write-Host "Failed to create service: $result"
        exit 1
    }
}

function Uninstall-PostmanService {
    Write-Host "Uninstalling Postman SAML Enforcer service..."
    
    # Stop and remove service if it exists
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Stopping and removing Windows service..."
        if ($service.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
        & sc.exe delete $ServiceName | Out-Null
    }
    
    # Stop any running daemon processes
    Write-Host "Stopping daemon processes..."
    $daemonProcesses = Get-WmiObject Win32_Process | Where-Object { 
        $_.Name -match "python" -and 
        $_.CommandLine -like "*saml_enforcer.py*" 
    }
    if ($daemonProcesses) {
        foreach ($process in $daemonProcesses) {
            try {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
                Write-Host "Stopped daemon process (PID: $($process.ProcessId))"
            } catch {
                Write-Host "Warning: Could not stop process $($process.ProcessId)"
            }
        }
    }
    
    # Remove hosts file entries
    Write-Host "Cleaning up hosts file..."
    $HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $HostsFile) {
        $hostsContent = Get-Content $HostsFile
        $cleanedContent = $hostsContent | Where-Object { $_ -notmatch "127\.0\.0\.1.*identity\.getpostman\.com" }
        if ($hostsContent.Count -ne $cleanedContent.Count) {
            $cleanedContent | Set-Content $HostsFile
            Write-Host "Removed hosts file entries"
        }
    }
    
    # Remove trusted certificates
    Write-Host "Removing trusted certificates..."
    $certs = Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object { 
        $_.Subject -like "*identity.getpostman.com*" -or $_.DnsNameList -like "*identity.getpostman.com*"
    }
    if ($certs) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        foreach ($cert in $certs) {
            try {
                $store.Remove($cert)
                Write-Host "Removed certificate: $($cert.Subject)"
            } catch {
                Write-Host "Warning: Could not remove certificate $($cert.Subject)"
            }
        }
        $store.Close()
    }
    
    # Clean up service logs
    Write-Host "Cleaning up service logs..."
    $logFiles = @(
        "C:\ProgramData\Postman\saml-enforcer-service.log",
        "C:\ProgramData\Postman\saml-enforcer-service.log.1",
        "C:\ProgramData\Postman\saml-enforcer-service.log.2"
    )
    foreach ($logFile in $logFiles) {
        if (Test-Path $logFile) {
            try {
                Remove-Item $logFile -Force
                Write-Host "Removed log file: $logFile"
            } catch {
                Write-Host "Warning: Could not remove log file $logFile"
            }
        }
    }
    
    # Remove empty ProgramData directory if it exists
    $programDataDir = "C:\ProgramData\Postman"
    if (Test-Path $programDataDir) {
        $items = Get-ChildItem $programDataDir -ErrorAction SilentlyContinue
        if (-not $items) {
            try {
                Remove-Item $programDataDir -Force
                Write-Host "Removed empty directory: $programDataDir"
            } catch {
                Write-Host "Warning: Could not remove directory $programDataDir"
            }
        }
    }
    
    Write-Host "Service uninstalled successfully"
}

function Test-PostmanDaemon {
    Write-Host "Starting Postman SAML Enforcer in test mode..."
    
    # Get Python executable (auto-installs if needed)
    $PythonExe = Get-PythonExecutable
    
    # Verify we have the daemon script
    if (-not (Test-Path $LocalPythonScript)) {
        Write-Host "Daemon script not found: $LocalPythonScript"
        Write-Host "Project structure validation failed"
        exit 1
    }
    
    # Start daemon in background
    Write-Host "Starting daemon process..."
    $daemonProcess = Start-Process -FilePath $PythonExe -ArgumentList $LocalPythonScript -PassThru -WindowStyle Hidden
    
    # Wait for daemon to initialize
    Start-Sleep -Seconds 3
    
    # Check if daemon process is still running
    try {
        $process = Get-Process -Id $daemonProcess.Id -ErrorAction Stop
        Write-Host "Test daemon started successfully (PID: $($daemonProcess.Id))"
        Write-Host "Daemon is running in test mode - not installed as system service"
        Write-Host "Use '.\install-service.ps1 stop' to stop the test daemon"
    } catch {
        Write-Host "Daemon failed to start - checking for port conflicts..."
        $portCheck = netstat -an | Select-String "127.0.0.1:443.*LISTENING"
        if ($portCheck) {
            Write-Host "Another process is using 127.0.0.1:443"
            Write-Host "Port conflict detected: $portCheck"
        }
        exit 1
    }
}

function Start-PostmanService {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        # Service is installed - use normal service start
        Write-Host "Starting Postman SAML Enforcer service..."
        
        try {
            Start-Service -Name $ServiceName
            Write-Host "Service started successfully"
        } catch {
            Write-Host "Failed to start service: $_"
            exit 1
        }
    } else {
        # Service not installed - fall back to test mode
        Write-Host "Service not installed. Starting in test mode..."
        Write-Host "For permanent deployment, run: .\install-service.ps1 install"
        Test-PostmanDaemon
    }
}

function Stop-PostmanService {
    Write-Host "Stopping Postman SAML Enforcer..."
    
    # Check for installed service first
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        try {
            Stop-Service -Name $ServiceName -Force
            Write-Host "Service stopped successfully"
        } catch {
            Write-Host "Failed to stop service: $_"
        }
    } else {
        # Check for test daemon processes
        $daemonProcesses = Get-WmiObject Win32_Process | Where-Object { 
            $_.Name -match "python" -and 
            $_.CommandLine -like "*saml_enforcer.py*" 
        }
        if ($daemonProcesses) {
            Write-Host "Stopping test daemon processes..."
            foreach ($process in $daemonProcesses) {
                try {
                    Stop-Process -Id $process.ProcessId -Force
                    Write-Host "Test daemon stopped successfully (PID: $($process.ProcessId))"
                } catch {
                    Write-Host "Warning: Could not stop process $($process.ProcessId)"
                }
            }
        } else {
            Write-Host "No service or daemon processes running"
        }
    }
}

function Get-PostmanServiceStatus {
    $hasService = $false
    $hasDaemon = $false
    
    # Check for installed service
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        $hasService = $true
        Write-Host "=== Service Status ==="
        
        $status = $service.Status
        $startType = (Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'").StartMode
        Write-Host "Service Status: $status"
        Write-Host "Start Type: $startType"
        
        if ($status -eq "Running") {
            $process = Get-Process | Where-Object { $_.ProcessName -like "*python*" -and $_.CommandLine -like "*saml_enforcer*" }
            if ($process) {
                Write-Host "Process ID: $($process.Id)"
            }
        }
    }
    
    # Check for test daemon processes
    $daemonProcesses = Get-WmiObject Win32_Process | Where-Object { 
        $_.Name -match "python" -and 
        $_.CommandLine -like "*saml_enforcer.py*" 
    }
    if ($daemonProcesses) {
        $hasDaemon = $true
        $daemonPids = ($daemonProcesses | ForEach-Object { $_.ProcessId }) -join ", "
        
        if ($hasService) {
            Write-Host ""
            Write-Host "=== Test Daemon Status ==="
        } else {
            Write-Host "=== Daemon Status ==="
        }
        
        Write-Host "Test Daemon: Running (PID(s): $daemonPids)"
        Write-Host "Mode: Direct execution (not installed as service)"
    }
    
    # Summary if nothing is running
    if (-not $hasService -and -not $hasDaemon) {
        Write-Host "Service: Not installed"
        Write-Host "Daemon: Not running"
        Write-Host ""
        Write-Host "To start: .\install-service.ps1 start"
        Write-Host "To install as service: .\install-service.ps1 install"
    }
}

function Clear-PostmanSessions {
    Write-Host "Clearing all Postman authentication sessions..."
    
    # Get Python executable (auto-installs if needed)
    $PythonExe = Get-PythonExecutable
    
    # Path to the session clearing script
    $SessionScript = "$ProjectRoot\scripts\clear_postman_sessions.py"
    
    if (-not (Test-Path $SessionScript)) {
        Write-Host "Session clearing script not found: $SessionScript"
        Write-Host "Project structure validation failed"
        exit 1
    }
    
    # Run the session clearing script
    Write-Host "Running session clearing script..."
    try {
        & $PythonExe $SessionScript
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Session clearing completed successfully"
            Write-Host "All Postman authentication sessions have been cleared"
        } else {
            Write-Host "Session clearing completed with warnings"
            Write-Host "Core session clearing functionality completed"
        }
    } catch {
        Write-Host "Error running session clearing script: $_"
        Write-Host "Session clearing may have completed partially"
    }
}


# Main execution
switch ($Action) {
    "install" { Install-PostmanService }
    "uninstall" { Uninstall-PostmanService }
    "start" { Start-PostmanService }
    "stop" { Stop-PostmanService }
    "status" { Get-PostmanServiceStatus }
    "srefresh" { Clear-PostmanSessions }
}