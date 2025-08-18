#############################################################################
# Clear Postman Sessions Script (Windows)
# 
# Removes Postman session cookies from all browsers and desktop client
# Useful for testing authentication flow and MDM-based session termination
#############################################################################

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "     Clearing All Postman Sessions" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  This will log you out of Postman everywhere" -ForegroundColor Yellow
Write-Host ""

# Function to clear Chrome cookies
function Clear-ChromeCookies {
    Write-Host "Clearing Chrome Postman cookies..." -ForegroundColor White
    
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
    if (Test-Path $chromePath) {
        # Stop Chrome if running
        Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        try {
            # Use SQLite to remove cookies (requires sqlite3.exe in PATH or script directory)
            if (Test-Path ".\sqlite3.exe") {
                & .\sqlite3.exe "$chromePath" "DELETE FROM cookies WHERE host_key LIKE '%postman.com%';"
            } else {
                # Alternative: rename cookies file to force regeneration
                Move-Item -Path $chromePath -Destination "$chromePath.bak" -Force
            }
            Write-Host "✓ Chrome cookies cleared" -ForegroundColor Green
        } catch {
            Write-Host "Chrome is running or database is locked. Please close Chrome and try again." -ForegroundColor Red
        }
    } else {
        Write-Host "Chrome cookies database not found" -ForegroundColor Gray
    }
}

# Function to clear Firefox cookies
function Clear-FirefoxCookies {
    Write-Host "Clearing Firefox Postman cookies..." -ForegroundColor White
    
    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        # Stop Firefox if running
        Stop-Process -Name firefox -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        # Find all Firefox profiles and clear cookies
        Get-ChildItem -Path $firefoxPath -Filter "*.default*" | ForEach-Object {
            $cookiesPath = Join-Path $_.FullName "cookies.sqlite"
            if (Test-Path $cookiesPath) {
                try {
                    if (Test-Path ".\sqlite3.exe") {
                        & .\sqlite3.exe "$cookiesPath" "DELETE FROM moz_cookies WHERE host LIKE '%postman.com%';"
                    } else {
                        # Alternative: rename cookies file
                        Move-Item -Path $cookiesPath -Destination "$cookiesPath.bak" -Force
                    }
                } catch {
                    Write-Host "Firefox is running or database is locked." -ForegroundColor Red
                }
            }
        }
        Write-Host "✓ Firefox cookies cleared" -ForegroundColor Green
    } else {
        Write-Host "Firefox profiles not found" -ForegroundColor Gray
    }
}

# Function to clear Edge cookies
function Clear-EdgeCookies {
    Write-Host "Clearing Edge Postman cookies..." -ForegroundColor White
    
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies"
    if (Test-Path $edgePath) {
        # Stop Edge if running
        Stop-Process -Name msedge -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        try {
            if (Test-Path ".\sqlite3.exe") {
                & .\sqlite3.exe "$edgePath" "DELETE FROM cookies WHERE host_key LIKE '%postman.com%';"
            } else {
                # Alternative: rename cookies file
                Move-Item -Path $edgePath -Destination "$edgePath.bak" -Force
            }
            Write-Host "✓ Edge cookies cleared" -ForegroundColor Green
        } catch {
            Write-Host "Edge is running or database is locked. Please close Edge and try again." -ForegroundColor Red
        }
    } else {
        Write-Host "Edge cookies database not found" -ForegroundColor Gray
    }
}

# Function to clear Postman Desktop App data
function Clear-PostmanDesktop {
    Write-Host "Clearing Postman Desktop App session..." -ForegroundColor White
    
    # Stop Postman if running
    Stop-Process -Name Postman -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    
    # Postman Desktop stores data in multiple locations
    $postmanPaths = @(
        "$env:APPDATA\Postman\cookies",
        "$env:APPDATA\Postman\Cache",
        "$env:APPDATA\Postman\CachedData",
        "$env:APPDATA\Postman\Session Storage",
        "$env:APPDATA\Postman\Local Storage",
        "$env:APPDATA\Postman\proxy",
        "$env:LOCALAPPDATA\Postman\cookies",
        "$env:LOCALAPPDATA\Postman\Cache"
    )
    
    foreach ($path in $postmanPaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Host "✓ Postman Desktop session cleared" -ForegroundColor Green
}

# Function to clear Windows Credential Manager entries
function Clear-CredentialManager {
    Write-Host "Checking for Postman entries in Windows Credential Manager..." -ForegroundColor White
    
    # List credentials related to Postman
    $creds = cmdkey /list | Select-String "postman"
    
    if ($creds) {
        Write-Host "Found Postman entries in Credential Manager" -ForegroundColor Yellow
        $response = Read-Host "Clear credential entries too? (y/N)"
        
        if ($response -eq 'y' -or $response -eq 'Y') {
            # Remove Postman-related credentials
            cmdkey /delete:target=postman.com 2>$null
            cmdkey /delete:target=identity.getpostman.com 2>$null
            cmdkey /delete:target=go.postman.co 2>$null
            
            Write-Host "✓ Credential Manager entries cleared" -ForegroundColor Green
        }
    } else {
        Write-Host "No Postman credential entries found" -ForegroundColor Gray
    }
}

# Main execution
Write-Host "Starting session cleanup..." -ForegroundColor White
Write-Host ""

# Clear browser cookies
Clear-ChromeCookies
Clear-FirefoxCookies
Clear-EdgeCookies

Write-Host ""

# Clear Postman Desktop
Clear-PostmanDesktop

Write-Host ""

# Optionally clear credential manager
Clear-CredentialManager

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "✅ Session cleanup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "1. Visit https://identity.getpostman.com to test authentication"
Write-Host "2. You should be redirected to your IDP for login"
Write-Host "3. After auth, you'll have a fresh Postman session"
Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan

exit 0