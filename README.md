# Postman SAML Enforcer

Enterprise authentication enforcement for Postman Desktop applications.

## The Problem

"How do we force our users to log in with our company SSO instead of personal accounts?" 

The request comes up constantly. Teams want to ensure that:
- Employees use corporate-managed accounts, not personal Gmail/Yahoo accounts
- All API usage is properly audited and tied to company identity
- Sensitive collections and environments stay within corporate boundaries
- Data exfiltration risks are effectively nullified (short of intentional malice)

Traditional approaches like blocking Postman entirely create terrible user experiences and drive employees to workarounds that are even less secure.

## The Solution

1. Configure SSO in Postman Enterprise
2. Enforce Device Trust for your SAML flow to ensure *only* company devices can access your Enterprise team.
3. Deploy this via MDM to all company devices

### *Done!*

This daemon provides seamless SAML enforcement by intelligently intercepting Postman's authentication flow. Instead of blocking access, it transparently redirects users to your enterprise SSO provider, eliminating the team selection screen and authentication method choices entirely.

**Why This is the Best Possible Solution:**

- Works on or off corporate network
- Eliminates accidental data exfiltration scenarios entirely
- Works with both Postman Desktop and web applications
- Encourages proper collaboration within the corporate workspace

*For Users:*
- Totally seamless UX - users are redirected to corporate login smoothly

*For IT:*
- Deploys alongside the Postman Enterprise App
- Centralized deployment through standard enterprise tools (SCCM, Jamf Pro, etc.)
- Works with existing SAML infrastructure (Okta, Azure AD, etc.)
- Comprehensive logging and monitoring capabilities
- Easy rollback if issues arise

## How It Works

### Why a Daemon is Necessary

Simple DNS redirection or basic HTTP redirects won't work for SAML enforcement because:

- **Parameter Transformation**: Authentication requests contain critical parameters (`auth_challenge`, `continue`, `team`) that must be preserved and transformed for proper SAML flow
- **Selective Interception**: Only specific authentication paths need redirection - everything else must proxy normally to maintain Postman functionality  
- **SSL Termination**: Browsers expect valid SSL certificates for `identity.getpostman.com` - the daemon generates and trusts certificates automatically
- **CDN Compatibility**: Real Postman servers use CDN infrastructure requiring proper SNI headers that simple redirects can't provide

### Technical Implementation

The daemon operates as an intelligent SSL proxy that:

1. **Hosts File Redirection**: Routes `identity.getpostman.com` to localhost
2. **Selective Interception**: Only intercepts authentication endpoints (`/login`, `/enterprise/login`, `/enterprise/login/authchooser`)
3. **Parameter Preservation**: Extracts and forwards authentication parameters to your SAML provider
4. **Transparent Proxying**: All other requests pass through to real Postman servers with proper SSL/SNI handling

This ensures normal Postman functionality while enforcing corporate authentication policies without breaking existing workflows.

## Quick Start

### Installation

**macOS:**
```bash
sudo service/macos/install-service.sh install
```

**Windows:**
```powershell
# Run as Administrator
.\service\windows\install-service.ps1 install
```

### Testing

**Run Locally and Test:**
```bash
# macOS
sudo service/macos/install-service.sh start
sudo service/macos/install-service.sh status

# Windows (as Administrator)
.\service\windows\install-service.ps1 start
.\service\windows\install-service.ps1 status
```

**Clear Postman Sessions (Fresh SAML Authentication):**
```bash
# macOS - Clear all Postman sessions from browsers and applications
sudo service/macos/install-service.sh srefresh

# Windows (as Administrator) - Clear all Postman sessions
.\service\windows\install-service.ps1 srefresh
```

**Test SAML Enforcement:**
```
1. Open a web browser and navigate to `https://postman.co`, flow should be automatic
2. Open Postman Desktop application and click "Sign In" - same SAML redirection should occur
``` 

### Uninstall

**Complete Removal:**
```bash
# macOS - removes service, certificates, hosts entries
sudo service/macos/install-service.sh uninstall

# Windows - removes service, certificates, hosts entries (as Administrator)
.\service\windows\install-service.ps1 uninstall
```

## Documentation

- **[macOS Service Guide](service/macos/README.md)** - LaunchDaemon installation and management
- **[Windows Service Guide](service/windows/README.md)** - Windows Service installation and management

## Configuration

Create `config/config.json` with your SAML settings:

```json
{
  "postman_team_name": "your-company-team",
  "saml_init_url": "https://identity.getpostman.com/sso/okta/your-tenant-id/init"
}
```

**Supported Identity Providers:**
- Okta: `https://identity.getpostman.com/sso/okta/tenant-id/init`
- Azure AD: `https://identity.getpostman.com/sso/adfs/tenant-id/init`
- Everything Else: `https://identity.getpostman.com/sso/saml/tenant-id/init`

## Session Management

The SAML enforcer includes comprehensive session clearing functionality to ensure fresh authentication flows:

### Clear All Postman Sessions

Use the `srefresh` command to clear all existing Postman authentication sessions:

```bash
# macOS
sudo service/macos/install-service.sh srefresh

# Windows (as Administrator)
.\service\windows\install-service.ps1 srefresh
```

**What this clears:**
- **Browser Cookies:** All Postman authentication cookies from Chrome, Firefox, Brave, Safari
- **Application Sessions:** Postman Desktop and Postman Enterprise session files
- **Process Management:** For the few applications that require restart (Firefox, Desktop Apps), does so gracefully

**When to use:**
- Initial deployment to ensure all users get fresh SAML authentication
- After changing SAML configuration or identity provider settings
- When users report authentication issues or cached login states
- As part of routine maintenance to enforce policy compliance

**Process Details:**
1. Detects and gracefully closes running Postman applications
2. Removes browser cookies for all Postman authentication domains
3. Deletes application session storage files
4. Restarts applications that were originally running
5. Next login will require fresh SAML authentication through your enterprise provider

This ensures users cannot bypass SAML enforcement through cached authentication tokens or sessions.

## Enterprise Deployment

This solution is designed for enterprise environments and supports:

- **Windows**: SCCM, Group Policy, Microsoft Intune, PowerShell DSC
- **macOS**: Jamf Pro, Apple Business Manager, MDM, .pkg distribution

**Common Features Across Both Platforms:**
- Automatic dependency installation (Python, certificates)
- System service registration with auto-restart on failure
- SSL certificate generation and trust management
- Hosts file management for DNS redirection
- Comprehensive uninstall removing all traces
- Test mode for development and debugging
- Health monitoring endpoints for enterprise monitoring

## Requirements

- **Administrative Privileges**: Required for port 443 binding and certificate trust
- **Network Access**: Connectivity to identity.getpostman.com and your SAML provider
- **Antivirus Exclusions**: May be needed for installation directories and processes

## Security Considerations

- Certificates are self-signed and automatically trusted during installation
- Only authentication paths are intercepted - all other traffic passes through normally
- SSL connections maintain proper SNI headers for CDN compatibility
- Local binding only (127.0.0.1) prevents external access
- Complete cleanup available through uninstall procedures