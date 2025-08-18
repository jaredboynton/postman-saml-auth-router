# macOS Deployment Guide for Postman Auth Router

## Overview

This guide provides comprehensive instructions for deploying the Postman SAML Authentication Router on macOS endpoints using JAMF Pro, Apple Business Manager, or standalone shell scripts.

### Enterprise Deployment Script Features (v1.0)

The JAMF deployment script includes enterprise-grade enhancements:

**Security & Compliance:**
- Input parameter validation (JAMF parameters 4-7)
- Integration with JAMF certificate payloads (preferred over self-signed)
- Secure keychain management
- No hardcoded credentials

**Reliability & Resilience:**
- Retry logic with exponential backoff for package downloads
- Enhanced certificate error handling
- LaunchDaemon with KeepAlive for automatic restart
- Comprehensive error checking for all operations

**Enterprise Integration:**
- JAMF receipt creation for inventory tracking
- Extension Attribute support for compliance monitoring
- Smart Group targeting based on Postman.app installation
- Unified Logging support capability

**Best Practices:**
- Fallback from certificate payloads to self-signed
- Proper file permissions (root:wheel ownership)
- Safe hosts file management with backup
- ISO-8601 date formats for consistency

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

**Important**: The daemon MUST listen on port 443 for HTTPS interception to work. Browsers always connect to port 443 for HTTPS URLs, and the hosts file can only redirect domains to IP addresses, not specific ports.

```bash
# Find process using port 443
sudo lsof -i :443

# Identify the process name
ps aux | grep <PID>
```

**Common Port 443 Conflicts on macOS:**
- **Apache httpd**: Stop with `sudo apachectl stop`
- **nginx**: Stop with `brew services stop nginx` or `sudo nginx -s stop`
- **Docker Desktop**: May use port 443 for certain configurations
- **Node.js applications**: Check for local development servers
- **Parallels Desktop**: May forward port 443 from VMs
- **VMware Fusion**: Check NAT configuration

**Resolution Options:**

### Option 1: Stop Conflicting Service (If Not Critical)
```bash
# Stop Apache
sudo apachectl stop
sudo launchctl unload -w /System/Library/LaunchDaemons/org.apache.httpd.plist

# Stop nginx (if installed via Homebrew)
brew services stop nginx

# Kill specific process
sudo kill -9 <PID>
```

### Option 2: Configure Reverse Proxy (Recommended for Development Machines)

If you need to keep the existing service on port 443, configure it to proxy Postman authentication traffic to the daemon on another available port.

**Choose any available port** for your daemon (e.g., 8443, 9443, 10443, or any unused port). The examples below use 8443, but replace with your chosen port.

#### **For nginx (most common on macOS)**:

1. Configure the daemon to listen on your chosen port:
   ```json
   # In config/config.json:
   {
     "advanced": {
       "daemon_port": 8443  # Or 9443, 10443, any available port
     }
   }
   ```

2. Add nginx configuration (update port to match):
   ```nginx
   # In /usr/local/etc/nginx/servers/postman-auth.conf
   server {
       listen 443 ssl;
       server_name identity.getpostman.com identity.postman.co;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       
       location / {
           proxy_pass https://127.0.0.1:8443;  # Update to your port
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_ssl_verify off;
       }
   }
   ```

3. Reload nginx:
   ```bash
   nginx -s reload
   # or if using Homebrew:
   brew services restart nginx
   ```

#### **For Apache (built-in on macOS)**:

1. Enable proxy modules in `/etc/apache2/httpd.conf`:
   ```apache
   LoadModule proxy_module libexec/apache2/mod_proxy.so
   LoadModule proxy_http_module libexec/apache2/mod_proxy_http.so
   LoadModule proxy_https_module libexec/apache2/mod_proxy_https.so
   ```

2. Add virtual host configuration (update port to match your daemon):
   ```apache
   # In /etc/apache2/other/postman-auth.conf
   <VirtualHost *:443>
       ServerName identity.getpostman.com
       ServerAlias identity.postman.co
       
       SSLEngine on
       SSLCertificateFile /path/to/cert.pem
       SSLCertificateKeyFile /path/to/key.pem
       
       ProxyPreserveHost On
       ProxyPass / https://127.0.0.1:8443/  # Update to your port
       ProxyPassReverse / https://127.0.0.1:8443/  # Update to your port
       SSLProxyEngine on
       SSLProxyVerify none
   </VirtualHost>
   ```

3. Restart Apache:
   ```bash
   sudo apachectl restart
   ```

### Option 3: macOS Port Forwarding (pfctl)

Use macOS's packet filter for port forwarding:

1. Choose any available port for your daemon and create forwarding rules:
   ```bash
   # Create pf rules file (replace 9443 with your chosen port)
   echo "rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 443 -> 127.0.0.1 port 9443" | sudo tee /etc/pf-postman.conf
   ```

2. Load and enable rules:
   ```bash
   # Load the rules
   sudo pfctl -f /etc/pf-postman.conf
   
   # Enable packet filter
   sudo pfctl -e
   
   # Check status
   sudo pfctl -s nat
   ```

3. Configure daemon to listen on your chosen port:
   ```json
   # Update config.json with your port:
   {
     "advanced": {
       "daemon_port": 9443  # Your chosen port
     }
   }
   ```

4. To remove forwarding:
   ```bash
   sudo pfctl -F nat  # Flush NAT rules
   sudo pfctl -d      # Disable packet filter
   ```

### Option 4: Using socat for Port Forwarding

For a quick solution, use socat to forward traffic:

```bash
# Install socat
brew install socat

# Run socat to forward 443 to your chosen port (e.g., 9443, 10443, etc.)
sudo socat TCP-LISTEN:443,fork,reuseaddr TCP:127.0.0.1:9443
# Replace 9443 with your daemon's port
```

### Option 5: Caddy Server (Modern Alternative)

Caddy provides automatic HTTPS and simple configuration:

1. Install Caddy:
   ```bash
   brew install caddy
   ```

2. Create Caddyfile (update port to match your daemon):
   ```
   # /usr/local/etc/Caddyfile
   identity.getpostman.com, identity.postman.co {
       reverse_proxy https://127.0.0.1:10443 {  # Use your daemon's port
           transport http {
               tls_insecure_skip_verify
           }
       }
   }
   ```

3. Run Caddy:
   ```bash
   sudo caddy run --config /usr/local/etc/Caddyfile
   ```

### Option 6: HAProxy for Advanced Routing

For SNI-based routing when multiple services need port 443:

1. Install HAProxy:
   ```bash
   brew install haproxy
   ```

2. Configure `/usr/local/etc/haproxy.cfg` (update ports to match your setup):
   ```
   frontend https_front
       bind *:443 ssl crt /path/to/combined.pem
       mode tcp
       option tcplog
       
       # Use SNI for routing
       use_backend postman_auth if { ssl_fc_sni -i identity.getpostman.com }
       use_backend postman_auth if { ssl_fc_sni -i identity.postman.co }
       default_backend original_service
   
   backend postman_auth
       mode tcp
       server daemon 127.0.0.1:11443 check  # Your daemon's port
   
   backend original_service
       mode tcp
       server original 127.0.0.1:8080 check  # Your existing service
   ```

3. Start HAProxy:
   ```bash
   brew services start haproxy
   ```

**Important Considerations**:
- The daemon can listen on **any available port** (8443, 9443, 10443, 11443, etc.) when properly proxied
- Update `/usr/local/bin/postman/config/config.json` to set your chosen port:
  ```json
  "advanced": {
      "daemon_port": 11443  // Your chosen port
  }
  ```
- Find available ports: `netstat -an | grep LISTEN | grep -v "127.0.0.1"`
- Ensure certificates are properly configured for both proxy and daemon
- Test the full authentication flow after configuration
- Consider using launchd to start the proxy service at boot
- Ports above 1024 don't require root privileges on most systems

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

## Rollback & Uninstall Procedures

### Method 1: Automated Uninstall (Recommended)

#### Via JAMF Pro Policy
Deploy the uninstall script through JAMF:
```bash
#!/bin/bash
# JAMF Uninstall Script
/usr/local/bin/postman/uninstall.sh
```

Or use the deployment script with uninstall mode:
```bash
/path/to/deploy_jamf.sh uninstall
```

The uninstall process will:
1. Stop and unload LaunchDaemon
2. Remove plist file
3. Remove hosts file entries (using safe markers)
4. Remove certificates from System keychain
5. Delete installation directory
6. Remove JAMF receipts
7. Clean up logs (optional)

#### Via JAMF Extension Attribute
Create an Extension Attribute to track and trigger uninstalls:
```bash
#!/bin/bash
# Extension Attribute: Postman Auth Router Removal Status

if [[ -f "/usr/local/bin/postman/uninstall.sh" ]]; then
    # Run uninstall if flagged for removal
    if [[ -f "/var/tmp/remove_postman_auth" ]]; then
        /usr/local/bin/postman/uninstall.sh
        rm -f /var/tmp/remove_postman_auth
        echo "<result>Removed</result>"
    else
        echo "<result>Installed</result>"
    fi
else
    echo "<result>Not Installed</result>"
fi
```

### Method 2: Remote Uninstall via JAMF

For help desk teams to remotely uninstall:

1. **JAMF Remote Command**:
   ```bash
   # Create uninstall policy in JAMF Pro
   # Scope to specific devices or Smart Groups
   # Execute command:
   /usr/local/bin/postman/uninstall.sh
   ```

2. **Self Service Removal**:
   - Add uninstall script to JAMF Self Service
   - Allow users to remove if needed
   - Monitor via Extension Attributes

### Method 3: Manual Cleanup

```bash
# Run full cleanup script
sudo ./scripts/daemon_manager.sh cleanup

# Or manual steps if needed:
sudo launchctl unload /Library/LaunchDaemons/com.postman.authrouter.plist
sudo rm -f /Library/LaunchDaemons/com.postman.authrouter.plist
sudo rm -rf /usr/local/bin/postman
sudo rm -rf /var/log/postman

# Remove hosts entries (between markers)
sudo sed -i.bak '/# BEGIN POSTMAN-AUTH-ROUTER-JAMF/,/# END POSTMAN-AUTH-ROUTER-JAMF/d' /etc/hosts

# Remove certificates
sudo security find-certificate -c "identity.getpostman.com" -a -Z | \
    awk '/SHA-1/{print $NF}' | \
    xargs -I {} sudo security delete-certificate -Z {} /Library/Keychains/System.keychain

# Remove JAMF receipts
sudo rm -f /private/var/db/receipts/com.postman.authrouter.*

# Flush DNS cache
sudo dscacheutil -flushcache
```

### Uninstall Script (Embedded in Deployment)

The deployment script creates an uninstall script at `/usr/local/bin/postman/uninstall.sh`:
```bash
#!/bin/bash
# Postman Auth Router Uninstall Script

echo "Uninstalling Postman Auth Router..."

# Stop and unload service
launchctl unload /Library/LaunchDaemons/com.postman.authrouter.plist 2>/dev/null

# Remove plist
rm -f /Library/LaunchDaemons/com.postman.authrouter.plist

# Remove hosts entries
sed -i.bak '/# BEGIN POSTMAN-AUTH-ROUTER-JAMF/,/# END POSTMAN-AUTH-ROUTER-JAMF/d' /etc/hosts

# Remove certificates
security find-certificate -c "identity.getpostman.com" -a -Z | \
    awk '/SHA-1/{print $NF}' | \
    xargs -I {} security delete-certificate -Z {} /Library/Keychains/System.keychain 2>/dev/null

# Remove installation directory
rm -rf /usr/local/bin/postman

# Remove logs (optional)
# rm -rf /var/log/postman

# Remove receipt
rm -f /private/var/db/receipts/com.postman.authrouter.*

echo "Uninstall completed"
```

### Compliance Monitoring

Monitor uninstall success via JAMF:
```bash
# Smart Group criteria for "Needs Removal"
# Extension Attribute: Postman Auth Router Status
# Value: "Not Installed" or "Removed"
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