# MDM Implementation Plan - Based on HAR Analysis

## Executive Summary
Precise implementation plan based on actual authentication flow analysis from HAR captures, designed for enterprise MDM deployment to force SAML-only authentication.

## Authentication Flow Analysis (From HAR Files)

### Normal Flow (Without Daemon):
```
1. /client-auth/confirm → Generates auth_challenge
2. /client-auth/start → Redirects with auth_challenge
3. /login?auth_challenge=XXX → User sees login page (200 OK)
4. /enterprise/login → User enters team name
5. /enterprise/login/authchooser → User selects auth method
6. /sso/okta/.../init → SAML redirect to Okta
7. Okta authentication → User authenticates
8. /sso/okta/.../callback → SAML response
9. identity.postman.co/continue?state=AAA → OAuth continuation
10. identity.postman.com/continue?state=BBB → Cross-domain state
11. id.gw.postman.com/continue?state=CCC → Final gateway
12. /browser-auth/success → Complete
```

### With Daemon (Current Issue):
```
1-2. Same as normal
3. /login → 302 redirect to SAML (skips team/method)
4. SAML flow completes
5. identity.postman.co/continue → OK
6. identity.postman.com/continue → LOOPS 19 times
7. 401 Unauthorized
```

### Root Cause:
`identity.postman.com` in /etc/hosts intercepts OAuth continuation that must reach real server.

## Implementation Strategy

### Approach 1: Dynamic Hosts Management (Recommended for Enterprise)

#### State Machine Design
```python
class PostmanAuthStateMachine:
    """
    Track authentication flow and dynamically adjust interception
    """
    
    STATES = {
        'IDLE': {
            'hosts': [],  # No interception
            'next': 'AUTH_INIT'
        },
        'AUTH_INIT': {
            'hosts': ['identity.getpostman.com'],  # Intercept initial auth
            'triggers': ['/client-auth/confirm', '/client/login'],
            'next': 'LOGIN_REDIRECT'
        },
        'LOGIN_REDIRECT': {
            'hosts': ['identity.getpostman.com'],  # Keep intercepting
            'triggers': ['/login'],
            'action': 'redirect_to_saml',  # Force SAML
            'next': 'SAML_FLOW'
        },
        'SAML_FLOW': {
            'hosts': ['identity.postman.co'],  # Only intercept callback
            'triggers': ['/sso/okta'],
            'next': 'OAUTH_CONTINUATION'
        },
        'OAUTH_CONTINUATION': {
            'hosts': [],  # NO interception - critical!
            'triggers': ['/continue'],
            'next': 'COMPLETE'
        },
        'COMPLETE': {
            'hosts': [],
            'reset_after': 5  # seconds
        }
    }
```

#### Critical Implementation Details

**1. Initial Setup (State: IDLE → AUTH_INIT)**
```bash
# When Postman Desktop launches or user clicks Sign In
# Add to hosts:
echo "127.0.0.1 identity.getpostman.com" >> /etc/hosts
```

**2. Login Interception (State: LOGIN_REDIRECT)**
```python
def handle_login_request(request):
    if 'auth_challenge' in request.params:
        # Desktop flow - has auth_challenge
        team = config['team_name']  # e.g., 'postman'
        saml_url = f"/sso/okta/db1b1a3764f24213906d682e26fd366f/init"
        params = {
            'team': team,
            'auth_challenge': request.params['auth_challenge'],
            'auth_device': request.params.get('auth_device'),
            'auth_device_version': request.params.get('auth_device_version')
        }
        return redirect(302, saml_url, params)
```

**3. SAML Flow (State: SAML_FLOW)**
```bash
# Before SAML callback, adjust hosts:
echo "127.0.0.1 identity.postman.co" >> /etc/hosts
# Remove identity.getpostman.com - no longer needed
sed -i '' '/identity.getpostman.com/d' /etc/hosts
```

**4. OAuth Continuation (State: OAUTH_CONTINUATION) - CRITICAL**
```bash
# MUST remove ALL interception during OAuth continuation
sed -i '' '/identity.postman.co/d' /etc/hosts
sed -i '' '/identity.postman.com/d' /etc/hosts  # Never add this!
sed -i '' '/id.gw.postman.com/d' /etc/hosts     # Never add this!

# Let these domains reach real servers:
# - identity.postman.co → identity.postman.com (real)
# - identity.postman.com → id.gw.postman.com (real)
# - id.gw.postman.com → identity.getpostman.com (real)
```

**5. Success Detection (State: COMPLETE)**
```python
def detect_success(request):
    if request.path == '/browser-auth/success':
        # Authentication complete
        # Clean up all hosts entries
        cleanup_hosts()
        return True
```

### Approach 2: Minimal Static Interception (Current Approach - Fixed)

#### Correct Hosts Configuration
```bash
# ONLY these two entries - NEVER add identity.postman.com
echo "127.0.0.1 identity.getpostman.com" >> /etc/hosts
echo "127.0.0.1 identity.postman.co" >> /etc/hosts
```

#### Updated Daemon Logic
```python
def handle_request(request):
    host = request.headers['Host']
    
    # CRITICAL: Check which domain we're actually intercepting
    if host == 'identity.getpostman.com':
        if request.path == '/login' and 'auth_challenge' in request.params:
            # Force SAML for Desktop flow
            return redirect_to_saml(request)
        else:
            # Pass through everything else
            return proxy_to_real_server(request)
            
    elif host == 'identity.postman.co':
        # Only proxy SAML callbacks, pass through
        return proxy_to_real_server(request)
    
    # Should never reach here with correct hosts
    return error(500, "Unexpected domain")
```

## MDM Deployment Package

### Package Structure
```
postman-saml-enforcement.pkg/
├── payload/
│   ├── /usr/local/postman-auth/
│   │   ├── daemon                    # Main daemon binary
│   │   ├── state-manager             # Tracks auth flow state
│   │   ├── hosts-manager             # Manages /etc/hosts
│   │   └── config.json               # Configuration
│   ├── /Library/LaunchDaemons/
│   │   └── com.company.postman-auth.plist
│   └── /etc/postman-auth/
│       ├── cert.pem                  # SSL certificate
│       └── key.pem                   # SSL private key
├── scripts/
│   ├── preinstall                    # Backup current config
│   ├── postinstall                   # Start daemon, trust cert
│   └── uninstall                     # Clean removal script
└── Distribution.xml                  # Package metadata
```

### Installation Script (postinstall)
```bash
#!/bin/bash

# 1. Install SSL certificate
security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain \
    /etc/postman-auth/cert.pem

# 2. Set correct permissions
chmod 755 /usr/local/postman-auth/daemon
chmod 600 /etc/postman-auth/key.pem
chown -R root:wheel /usr/local/postman-auth

# 3. Configure initial hosts (minimal approach)
cp /etc/hosts /etc/hosts.backup.$(date +%Y%m%d)
echo "# Postman SAML Enforcement" >> /etc/hosts
echo "127.0.0.1 identity.getpostman.com" >> /etc/hosts
echo "127.0.0.1 identity.postman.co" >> /etc/hosts

# 4. Load daemon
launchctl load -w /Library/LaunchDaemons/com.company.postman-auth.plist

# 5. Verify daemon is running
sleep 2
if launchctl list | grep -q "com.company.postman-auth"; then
    echo "✅ Postman SAML enforcement installed successfully"
    exit 0
else
    echo "❌ Failed to start daemon"
    exit 1
fi
```

### LaunchDaemon Configuration
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.company.postman-auth</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/postman-auth/daemon</string>
        <string>--config</string>
        <string>/usr/local/postman-auth/config.json</string>
        <string>--mode</string>
        <string>enforce</string>
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    
    <key>StandardOutPath</key>
    <string>/var/log/postman-auth.log</string>
    
    <key>StandardErrorPath</key>
    <string>/var/log/postman-auth.error.log</string>
    
    <key>RequireSuccess</key>
    <true/>
</dict>
</plist>
```

### Configuration File (config.json)
```json
{
    "mode": "enforce",
    "team_name": "postman",
    "saml_tenant_id": "db1b1a3764f24213906d682e26fd366f",
    
    "interception_rules": {
        "always_intercept": [
            {"host": "identity.getpostman.com", "path": "/login"},
            {"host": "identity.getpostman.com", "path": "/enterprise/login"}
        ],
        "never_intercept": [
            {"host": "identity.postman.com", "path": "*"},
            {"host": "id.gw.postman.com", "path": "*"}
        ],
        "pass_through": [
            {"host": "identity.getpostman.com", "path": "/client-auth/*"},
            {"host": "*", "path": "/continue"}
        ]
    },
    
    "ssl_config": {
        "cert_path": "/etc/postman-auth/cert.pem",
        "key_path": "/etc/postman-auth/key.pem",
        "listen_port": 443
    },
    
    "logging": {
        "level": "INFO",
        "file": "/var/log/postman-auth.log",
        "max_size_mb": 100,
        "max_backups": 5
    },
    
    "monitoring": {
        "health_check_port": 8443,
        "metrics_enabled": true,
        "alert_on_bypass_attempt": true
    }
}
```

## JAMF Deployment

### Smart Group
```xml
<computer_group>
    <name>Postman SAML Enforcement Targets</name>
    <criteria>
        <criterion>
            <name>Application Title</name>
            <search_type>has</search_type>
            <value>Postman.app</value>
        </criterion>
    </criteria>
</computer_group>
```

### Policy Configuration
```xml
<policy>
    <name>Deploy Postman SAML Enforcement</name>
    <scope>
        <computer_groups>
            <computer_group>Postman SAML Enforcement Targets</computer_group>
        </computer_groups>
    </scope>
    <trigger>recurring</trigger>
    <frequency>Once per computer</frequency>
    <packages>
        <package>postman-saml-enforcement.pkg</package>
    </packages>
    <scripts>
        <script>verify-postman-auth.sh</script>
    </scripts>
    <restart>No</restart>
</policy>
```

### Extension Attribute (Monitoring)
```bash
#!/bin/bash
# JAMF Extension Attribute: Postman SAML Status

if launchctl list | grep -q "com.company.postman-auth"; then
    # Check if daemon is intercepting correctly
    if curl -s https://identity.getpostman.com/health 2>/dev/null | grep -q "daemon-active"; then
        echo "<result>Active - Enforcing</result>"
    else
        echo "<result>Running - Not Intercepting</result>"
    fi
else
    echo "<result>Not Installed</result>"
fi
```

## Windows/SCCM Deployment

### PowerShell Installation Script
```powershell
# Install-PostmanSAMLEnforcement.ps1

# 1. Stop any existing service
Stop-Service -Name "PostmanAuthService" -ErrorAction SilentlyContinue

# 2. Install files
Copy-Item -Path ".\files\*" -Destination "C:\Program Files\PostmanAuth\" -Recurse -Force

# 3. Install certificate
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import("C:\Program Files\PostmanAuth\cert.pfx", "password", "PersistKeySet,MachineKeySet")
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

# 4. Modify hosts file
$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
Add-Content -Path $hostsPath -Value "`n# Postman SAML Enforcement"
Add-Content -Path $hostsPath -Value "127.0.0.1 identity.getpostman.com"
Add-Content -Path $hostsPath -Value "127.0.0.1 identity.postman.co"

# 5. Install and start service
New-Service -Name "PostmanAuthService" `
    -BinaryPathName "C:\Program Files\PostmanAuth\daemon.exe" `
    -DisplayName "Postman SAML Enforcement" `
    -StartupType Automatic

Start-Service -Name "PostmanAuthService"
```

## Monitoring & Alerting

### Key Metrics to Track
```python
metrics = {
    'auth_attempts_total': Counter(),
    'saml_redirects': Counter(),
    'bypass_attempts': Counter(),
    'success_rate': Gauge(),
    'daemon_uptime': Gauge(),
    'hosts_modifications': Counter(),
    'certificate_expiry_days': Gauge()
}
```

### Alert Conditions
- Bypass attempt detected
- Daemon not running > 5 minutes
- Success rate < 95%
- Certificate expires in < 30 days
- Hosts file manually modified

## Rollback Procedure

### Immediate Rollback (Emergency)
```bash
#!/bin/bash
# emergency-rollback.sh

# 1. Stop daemon
launchctl unload /Library/LaunchDaemons/com.company.postman-auth.plist

# 2. Restore hosts file
cp /etc/hosts.backup.* /etc/hosts

# 3. Remove certificate
security delete-certificate -c "identity.getpostman.com" \
    /Library/Keychains/System.keychain

# 4. Notify users
osascript -e 'display notification "Postman auth enforcement removed. Please restart Postman." with title "IT Update"'
```

## Success Criteria

✅ **Deployment Success When:**
- 100% of Postman users authenticate via SAML
- 0 bypass attempts succeed
- No impact to other applications
- OAuth continuation works properly (no loops)
- Both Desktop and Web flows work

## Timeline

- **Week 1**: Test package on IT team (10 machines)
- **Week 2**: Pilot with early adopters (100 machines)
- **Week 3**: Deploy to 25% of fleet
- **Week 4**: Deploy to 50% of fleet
- **Week 5**: Full deployment
- **Week 6**: Remove rollback option, permanent enforcement