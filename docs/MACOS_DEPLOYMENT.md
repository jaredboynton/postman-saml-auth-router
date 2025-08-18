# macOS Deployment Guide for Postman Auth Router

## Overview

This guide provides comprehensive instructions for deploying the Postman SAML Authentication Router on macOS endpoints using JAMF Pro, Apple Business Manager, or standalone shell scripts.

## Prerequisites

### System Requirements
- **macOS 10.15** (Catalina) or later (macOS 14 Sonoma supported)
- **Python 3.8+** installed (included in macOS 12.3+)
- **Administrator privileges** for installation
- **System Integrity Protection (SIP)** compatible

### Optional Components
- **Homebrew** for easier Python management
- **Terminal** or **iTerm2** for better command line experience

## Local Testing & Development

### Quick Setup (Standalone)

1. **Open Terminal as Administrator**
   ```bash
   # Open Terminal and elevate to root
   sudo -i
   ```

2. **Verify Python Installation**
   ```bash
   # Check Python version
   python3 --version
   
   # If missing, install via Homebrew or download from python.org
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   brew install python@3.11
   ```

3. **Configure and Run**
   ```bash
   # Navigate to project directory
   cd /path/to/postman_redirect_daemon
   
   # Configure your IdP settings
   cp config/config.json.template config/config.json
   nano config/config.json
   
   # Run setup
   sudo ./scripts/scripts/daemon_manager.sh setup
   ```

### Testing the Deployment

After setup completes:

1. **Run Preflight Checks**
   ```bash
   sudo ./scripts/scripts/daemon_manager.sh preflight
   ```

2. **Test Authentication**
   - Browser: Navigate to https://postman.co
   - Desktop: Open Postman Desktop application
   - Should redirect to your SAML IdP

3. **Monitor Logs**
   ```bash
   sudo ./scripts/scripts/daemon_manager.sh logs
   ```

## Enterprise Deployment

### Method 1: JAMF Pro

#### Package Preparation

1. **Create deployment package** with the following structure:
   ```
   PostmanAuthRouter.pkg
   ├── payload/
   │   ├── usr/local/postman-auth/
   │   │   ├── scripts/daemon_manager.sh
   │   │   ├── src/auth_router_final.py
   │   │   └── config/config.json.template
   │   ├── Library/LaunchDaemons/
   │   │   └── com.company.postman-auth.plist
   │   └── etc/postman-auth/
   │       ├── cert.pem
   │       └── key.pem
   └── scripts/
       ├── preinstall
       ├── postinstall
       └── preremove
   ```

2. **Upload to JAMF Pro** package distribution point

#### JAMF Pro Configuration

1. **Create Policy**:
   - Navigate to: Computers > Policies > New
   - Display Name: `Postman Auth Router Deployment`
   - Trigger: Recurring Check-in
   - Execution Frequency: Once per computer

2. **Package Configuration**:
   - Add package: `PostmanAuthRouter.pkg`
   - Action: Install
   - FUT (Fill User Template): No
   - FEU (Fill Existing Users): No

3. **Script Parameters** (via Policy Scripts):
   ```bash
   #!/bin/bash
   # Parameter 4: Postman Team Name
   # Parameter 5: Okta Tenant ID
   # Parameter 6: IdP URL
   
   /usr/local/postman-auth/scripts/daemon_manager.sh setup \
       --team-name "$4" \
       --okta-tenant "$5" \
       --idp-url "$6"
   ```

4. **Scope**:
   - Target computers: Smart Group with Postman.app installed
   - Limitations: None
   - Exclusions: Computers with existing auth router

#### Smart Group Creation

Create a Smart Group to target devices with Postman:

```xml
<computer_group>
    <name>Postman Users</name>
    <is_smart>true</is_smart>
    <criteria>
        <criterion>
            <name>Application Title</name>
            <search_type>has</search_type>
            <value>Postman.app</value>
        </criterion>
        <criterion>
            <and_or>and</and_or>
            <name>Operating System Version</name>
            <search_type>greater than or equal</search_type>
            <value>10.15</value>
        </criterion>
    </criteria>
</computer_group>
```

#### Extension Attribute (Compliance Monitoring)

Create an Extension Attribute for monitoring deployment status:

```bash
#!/bin/bash
# Extension Attribute: Postman Auth Router Status

# Check if LaunchDaemon is loaded and running
if launchctl list | grep -q "com.company.postman-auth"; then
    # Check if daemon is actually intercepting
    if curl -s --max-time 5 https://identity.getpostman.com/health 2>/dev/null | grep -q "daemon-active"; then
        echo "<result>Active - Enforcing</result>"
    else
        echo "<result>Installed - Not Active</result>"
    fi
else
    echo "<result>Not Installed</result>"
fi
```

### Method 2: Apple Business Manager + MDM

For organizations using Apple Business Manager with third-party MDM:

#### Configuration Profile Creation

1. **Create Custom Settings Payload**:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
       "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>PayloadContent</key>
       <array>
           <dict>
               <key>PayloadType</key>
               <string>com.apple.security.plist</string>
               <key>PayloadDisplayName</key>
               <string>Postman Auth Configuration</string>
               <key>PostmanTeamName</key>
               <string>YOUR_TEAM_NAME</string>
               <key>OktaTenantId</key>
               <string>YOUR_OKTA_TENANT</string>
           </dict>
       </array>
   </dict>
   </plist>
   ```

2. **Deploy Package via MDM**:
   - Use your MDM's app deployment feature
   - Target devices based on inventory data
   - Monitor installation status

### Method 3: Munki (Open Source)

For organizations using Munki package management:

1. **Create pkginfo file**:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
       "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>name</key>
       <string>PostmanAuthRouter</string>
       <key>display_name</key>
       <string>Postman Auth Router</string>
       <key>version</key>
       <string>1.0.0</string>
       <key>minimum_os_version</key>
       <string>10.15.0</string>
       <key>installer_item_location</key>
       <string>PostmanAuthRouter-1.0.0.pkg</string>
       <key>uninstall_method</key>
       <string>uninstall_script</string>
       <key>uninstall_script</key>
       <string>#!/bin/bash
   /usr/local/postman-auth/scripts/daemon_manager.sh cleanup</string>
   </dict>
   </plist>
   ```

2. **Add to catalog**:
   ```bash
   makecatalog /path/to/munki_repo
   ```

## Enterprise Certificate Management

### Using Enterprise CA Certificates

Instead of self-signed certificates, use your enterprise Certificate Authority:

1. **Generate Certificate Request**:
   ```bash
   # Create configuration file
   cat > postman-auth.conf << EOF
   [req]
   distinguished_name = req_distinguished_name
   req_extensions = v3_req
   prompt = no
   
   [req_distinguished_name]
   CN = identity.getpostman.com
   O = Your Organization
   C = US
   
   [v3_req]
   basicConstraints = CA:FALSE
   keyUsage = nonRepudiation, digitalSignature, keyEncipherment
   subjectAltName = @alt_names
   
   [alt_names]
   DNS.1 = identity.getpostman.com
   DNS.2 = identity.postman.com
   DNS.3 = identity.postman.co
   DNS.4 = localhost
   IP.1 = 127.0.0.1
   EOF
   
   # Generate CSR and private key
   openssl req -new -newkey rsa:2048 -keyout postman-auth.key \
       -out postman-auth.csr -config postman-auth.conf -nodes
   ```

2. **Submit to Enterprise CA**:
   - Use your organization's certificate request process
   - Request a Web Server certificate template
   - Ensure all required SANs are included

3. **Deploy via JAMF/MDM**:
   - Add certificate to System Keychain
   - Set trust settings to "Always Trust" for SSL
   - Update deployment scripts to use enterprise certificate

### Certificate Deployment via JAMF

1. **Create Certificate Payload**:
   - Navigate to: Configuration Profiles > New
   - Add Payload: Certificate
   - Upload your enterprise certificate (.cer format)

2. **Configure Trust Settings**:
   - Certificate Name: `identity.getpostman.com`
   - Allow all applications to access: Yes
   - Use for SSL: Always Trust

3. **Scope and Deploy**:
   - Target same Smart Group as auth router
   - Deploy before auth router installation

## Troubleshooting

### Common Issues

#### Python Not Found or Wrong Version
```bash
# Check Python installation
python3 --version
which python3

# Install via Homebrew
brew install python@3.11

# Or use system Python (macOS 12.3+)
/usr/bin/python3 --version
```

#### Certificate Trust Issues
```bash
# Manually trust certificate (requires admin)
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain \
    /etc/postman-auth/cert.pem

# Verify certificate trust
security find-certificate -c "identity.getpostman.com" \
    /Library/Keychains/System.keychain

# Check trust settings
security dump-trust-settings -d
```

#### Port 443 Already in Use
```bash
# Find process using port 443
sudo lsof -i :443

# Kill specific process (replace PID)
sudo kill -9 <PID>

# Alternative: use netstat
netstat -an | grep :443
```

#### LaunchDaemon Won't Start
```bash
# Check daemon status
sudo launchctl list | grep postman-auth

# Load daemon manually
sudo launchctl load -w /Library/LaunchDaemons/com.company.postman-auth.plist

# Check for errors
sudo launchctl error <service-target>

# View system logs
log show --predicate 'subsystem == "com.company.postman-auth"' --last 1h
```

#### Hosts File Permission Issues
```bash
# Check hosts file permissions
ls -la /etc/hosts

# Fix permissions if needed
sudo chmod 644 /etc/hosts
sudo chown root:wheel /etc/hosts

# Backup and restore hosts
sudo cp /etc/hosts /etc/hosts.backup
```

### Log Locations

- **Daemon logs**: `/var/log/postman-auth.log`
- **System logs**: `log show --predicate 'subsystem == "com.company.postman-auth"'`
- **JAMF logs**: `/var/log/jamf.log`
- **Installation logs**: `/var/log/install.log`

### Validation Commands

```bash
# Full system check
sudo ./scripts/scripts/daemon_manager.sh preflight

# Manual health check
curl -s https://identity.getpostman.com/health

# Check all components
sudo launchctl list | grep postman-auth
grep -E "(identity\.|postman\.)" /etc/hosts
security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain

# Test daemon response
curl -k -H "Host: identity.getpostman.com" https://127.0.0.1/health
```

## Rollback Procedure

If deployment needs to be reversed:

```bash
# Run full cleanup
sudo ./scripts/scripts/daemon_manager.sh cleanup

# Manual cleanup if needed
sudo launchctl unload /Library/LaunchDaemons/com.company.postman-auth.plist
sudo rm -f /Library/LaunchDaemons/com.company.postman-auth.plist
sudo rm -rf /usr/local/postman-auth
sudo rm -rf /etc/postman-auth

# Remove hosts entries
sudo ./scripts/scripts/daemon_manager.sh remove-hosts

# Remove certificate
sudo security delete-certificate -c "identity.getpostman.com" \
    /Library/Keychains/System.keychain
```

## Security Considerations

### Best Practices

1. **Use Enterprise Certificates** instead of self-signed
2. **Deploy via MDM** to prevent user tampering
3. **Monitor logs** centrally via your SIEM
4. **Use System Integrity Protection** (keep SIP enabled)
5. **Regular certificate rotation** per your PKI policy

### Privacy and Compliance

- Logs all authentication attempts locally
- No data transmitted outside the device
- Compatible with FileVault encryption
- Supports audit and compliance requirements
- GDPR/CCPA compliant (no personal data collection)

### macOS Security Features

- **Gatekeeper compatible**: Package can be signed and notarized
- **System Extensions**: No kernel extensions required
- **Hardened Runtime**: Compatible with security restrictions
- **Code Signing**: All components can be signed with Developer ID

## Advanced Configuration

### Custom LaunchDaemon Configuration

For advanced deployments, customize the LaunchDaemon:

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
        <string>/usr/local/postman-auth/src/auth_router_final.py</string>
        <string>--config</string>
        <string>/etc/postman-auth/config.json</string>
        <string>--mode</string>
        <string>enforce</string>
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>NetworkState</key>
        <true/>
    </dict>
    
    <key>ThrottleInterval</key>
    <integer>10</integer>
    
    <key>StandardOutPath</key>
    <string>/var/log/postman-auth.log</string>
    
    <key>StandardErrorPath</key>
    <string>/var/log/postman-auth.error.log</string>
    
    <key>RequireSuccess</key>
    <true/>
    
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
```

### Environment Variables

Set environment variables for advanced configuration:

```bash
# In LaunchDaemon or deployment script
export POSTMAN_AUTH_DEBUG=1
export POSTMAN_AUTH_LOG_LEVEL=DEBUG
export POSTMAN_AUTH_TIMEOUT=60
```

## Support

For issues specific to macOS deployment:
1. Check this guide's troubleshooting section
2. Review logs in `/var/log/postman-auth.log`
3. Verify all prerequisites are met
4. Test with `sudo ./scripts/scripts/daemon_manager.sh preflight`
5. Check System Integrity Protection status: `csrutil status`

---

*Last updated: 2025-08-17*