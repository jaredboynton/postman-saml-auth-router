# Postman SAML Authentication Enforcer

**Enterprise-grade SAML enforcement for Postman Web and Desktop applications**

A local authentication proxy that forces all Postman sign-ins through your corporate SSO provider, preventing shadow IT and ensuring compliance across your entire fleet.

## What This Does & How It Works

When users try to sign into Postman (Web or Desktop), they are automatically redirected to your company's SAML identity provider - no authentication choice, no personal accounts, just secure enterprise access.

```
┌───────────────────────────────────────────────────────────────────────────┐
│ STEP 1: Initial Login Attempt                                             │
├───────────────────────────────────────────────────────────────────────────┤
│ User (Browser/Desktop)                                                    │
│        → identity.getpostman.com                                          │
│        → 127.0.0.1:443                                                    │
│                                                                           │
│ Daemon evaluates:                                                         │
│   • Bypass detection                                                      │
│   • State: IDLE → AUTH_INIT                                               │
│        ↓                                                                  │
│   ✓ INTERCEPT → SAML redirect                                             │
└───────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌───────────────────────────────────────────────────────────────────────────┐
│ STEP 2: SAML Authentication                                               │
├───────────────────────────────────────────────────────────────────────────┤
│ Daemon state: AUTH_INIT → SAML_FLOW                                       │
│                                                                           │
│ Redirected to IdP (Okta / Azure / Ping)                                   │
│        → User authenticates                                               │
│        → SAML assertion generated                                         │
│                                                                           │
│ Returns to Postman with token                                             │
└───────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌───────────────────────────────────────────────────────────────────────────┐
│ STEP 3: OAuth Continuation                                                │
├───────────────────────────────────────────────────────────────────────────┤
│ SAML token returned                                                       │
│        → identity.postman.com                                             │
│        → 127.0.0.1:443                                                    │
│                                                                           │
│ Daemon evaluates:                                                         │
│   • State: SAML_FLOW → OAUTH_CONTINUATION                                 │
│        ↓                                                                  │
│   ✓ ALLOW → Proxy to real IP                                              │
└───────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌───────────────────────────────────────────────────────────────────────────┐
│ STEP 4: Session Established                                               │
├───────────────────────────────────────────────────────────────────────────┤
│ OAuth completes → Valid Postman session                                   │
│                                                                           │
│ State: OAUTH_CONTINUATION → IDLE                                          │
│                                                                           │
│ User authenticated                                                        │
│ (30s timeout returns to IDLE if no activity)                              │
└───────────────────────────────────────────────────────────────────────────┘
```

The daemon intercepts authentication requests and enforces SAML-only access through a sophisticated state machine that preserves OAuth flows while blocking bypass attempts.

**Key Benefits:**
- **100% SAML enforcement** for all Postman authentication flows
- **Works everywhere:** Office, home, VPN, coffee shop
- **Quick deployment** to devices via MDM, no network changes
- **No dependencies** - Pure Python standard library
- **99% data exfiltration prevention** when combined with Domain Capture and Device Trust. While this won't stop a copy-paster or an intentionally malicious actor, this should stop everything else.

## Security Highlights

- **Bypass Prevention**: Detects and blocks all known bypass techniques
- **Session Control**: Instant session termination for offboarding and fine-tuning session length via `clear_mac_sessions.sh` and `clear_win_sessions.ps1` scripts deployed via MDM
- **Audit Logging**: SIEM-ready structured logs
- **Certificate Security**: Enterprise CA support with MDM deployment
- **Process Protection**: Cannot be killed even with admin privileges when deployed via MDM

See [Security Documentation](docs/SECURITY.md) for complete details.

## Why This Is The Only Viable Solution

Organizations often ask: "Can we implement this with our existing security tools like CrowdStrike, Zscaler, or F5 instead?"

**Short Answer**: No. I analyzed every alternative approach extensively.

**Why Alternatives Fail**: OAuth authentication flows inherently require sophisticated session state management that enterprise security platforms fundamentally cannot provide:

- **OAuth Continuation Protection**: The daemon's 4-state machine is necessary to prevent dropping state tracking throughout the flow. All alternatives would break this, causing 401 authentication errors.
- **Desktop Flow Detection**: Complex two-step validation prevents replay attacks. Alternatives cannot track session state across requests.
- **Application-Specific Logic**: 4 layers of bypass prevention understanding application-specific parameters. Alternatives can be trivially bypassed.
- **Enterprise Infrastructure**: SNI-aware SSL proxy for Cloudflare, nslookup + fallback IPs for corporate firewalls, real-time SIEM metrics.

**What Alternatives Can Do**:
- **Detection & Alerting**: Monitor Postman usage
- **Complete Blocking**: Prevent all Postman access 
- ❌ **HOWEVER --** they cannot redirect while preserving OAuth

**The Technical Reality**: This is a fundamental OAuth architecture challenge, not a Postman limitation. Infrastructure tools operate at the wrong layer, and even dedicated OAuth proxy solutions struggle with session state management across any OAuth-enabled application.

**Comprehensive Analysis**: See [Alternative Analysis](docs/ALTERNATIVE_ANALYSIS.md) for detailed technical assessment with supporting research from CrowdStrike, Zscaler, F5, and OAuth security studies.

**Bottom Line**: Organizations wanting "SAML enforcement while maintaining OAuth application functionality" have exactly one viable option: application-aware proxy solutions like this local daemon approach.

## Local Testing & Management Commands

**Note**: These steps are for local testing and validation only. Production deployment uses MDM tools (JAMF, Intune, SCCM) which handle installation, configuration, and certificate management automatically. Management commands also work in MDM deployments for troubleshooting and status monitoring.

### macOS/Linux
```bash
# 1. Configure your IdP
cp config/config.json.template config/config.json
vi config/config.json  # Add team name & IdP details

# 2. Run setup (local testing only)
sudo ./scripts/daemon_manager.sh setup

# 3. Test authentication
open https://postman.co  # Should redirect to your IdP
```

### Windows
```powershell
# 1. Configure your IdP (Run as Administrator)
Copy-Item config\config.json.template config\config.json
notepad config\config.json

# 2. Run setup (local testing only)
.\scripts\daemon_manager.ps1 setup

# 3. Test authentication
Start-Process https://postman.co
```

### Management Commands
```bash
# Check status
sudo ./scripts/daemon_manager.sh status

# View health metrics
curl -k https://localhost:443/health

# Restart daemon
sudo ./scripts/daemon_manager.sh restart

# Emergency stop
sudo ./scripts/daemon_manager.sh cleanup
```

## Enterprise Deployment

**Supported MDM Platforms:**
- JAMF (macOS)
- Microsoft Intune (Windows)
- SCCM (Windows)
- Workspace ONE (Cross-platform)

**Supported Identity Providers:**
- Okta
- Azure AD
- Ping Identity
- Any SAML 2.0 provider

**Scale:** Deploy identically to 10 or 10,000 devices via MDM.

See platform-specific deployment guides: [macOS](docs/MACOS_DEPLOYMENT.md) and [Windows](docs/WINDOWS_DEPLOYMENT.md) for complete enterprise deployment instructions.

## Configuration Example

```json
{
  "postman_team_name": "your-team",
  "idp_config": {
    "idp_type": "okta",
    "okta_tenant_id": "dev-12345678"
  }
}
```

See [Configuration Guide](docs/CONFIGURATION.md) for all options.

## Project Structure

```
postman_redirect_daemon/
├── README.md                       # This file
│
├── scripts/                        # Management scripts
│   ├── daemon_manager.sh           # macOS/Linux management
│   └── daemon_manager.ps1          # Windows PowerShell management
│
├── src/                            # Source code
│   ├── auth_router_final.py        # Main daemon with state machine
│   └── dynamic_hosts/              # Optional hosts management
│       └── hosts_manager.py        # Runtime hosts file manager
│
├── config/                         # Configuration files
│   ├── config.json.template        # Configuration template
│   └── config.json                 # Your configuration (gitignored)
│
├── ssl/                            # SSL certificates (local testing only)
│   ├── cert.conf                   # Certificate configuration
│   ├── cert.pem                    # SSL certificate (generated for local testing)
│   └── key.pem                     # Private key (generated for local testing)
│
├── tools/                          # Utility scripts
│   ├── clear_mac_sessions.sh       # macOS session clearing
│   ├── clear_win_sessions.ps1      # Windows session clearing
│   ├── deploy_jamf.sh              # JAMF deployment helper
│   ├── deploy_intune.ps1           # Intune deployment template
│   └── deploy_sccm.ps1             # SCCM deployment template
│
└── docs/                           # Documentation
    ├── SECURITY.md                 # Security model & controls
    ├── ARCHITECTURE.md             # Technical architecture
    ├── CONFIGURATION.md            # Configuration reference
    ├── TROUBLESHOOTING.md          # Troubleshooting guide
    ├── ALTERNATIVE_ANALYSIS.md     # Why alternatives cannot work
    ├── TECHNICAL.md                # Implementation details
    ├── AUTHENTICATION_FLOW.md      # Flow analysis, useful for troubleshooting
    ├── MACOS_DEPLOYMENT.md         # macOS deployment guide
    └── WINDOWS_DEPLOYMENT.md       # Windows deployment guide

**Runtime Log Locations:**
- macOS/Linux: `/var/log/postman-auth.log`
- Windows: `C:\ProgramData\Postman\logs\postman-auth.log`

**Enterprise Deployment Notes:**
- SSL certificates: Enterprise deployments use certificates from your organization's CA, not the local ssl/ directory
- Configuration: Production config deployed via MDM, not local config.json file
- Port conflicts: If port 443 is in use, comprehensive reverse proxy and port forwarding solutions are documented in the deployment guides
```

## Documentation

### Planning & Evaluation
- [Security Model & Threat Analysis](docs/SECURITY.md) - Comprehensive security documentation
- [Architecture Overview](docs/ARCHITECTURE.md) - Technical design and components
- [Alternative Analysis](docs/ALTERNATIVE_ANALYSIS.md) - Why alternatives cannot work

### Implementation
- [macOS Deployment](docs/MACOS_DEPLOYMENT.md) - JAMF, Apple Business Manager, Munki deployment
- [Windows Deployment](docs/WINDOWS_DEPLOYMENT.md) - Intune, SCCM, Group Policy deployment
- [Configuration Reference](docs/CONFIGURATION.md) - All configuration options
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Common issues and solutions

### Additional Resources
- [Authentication Flow](docs/AUTHENTICATION_FLOW.md) - Detailed flow analysis as an FYI
- [Alternative Implementations](docs/ALTERNATIVE_IMPLEMENTATIONS.md) - Network-level and proxy integration options

## Troubleshooting

For deployment assistance or questions:
1. Check [Troubleshooting Guide](docs/TROUBLESHOOTING.md)
2. Review platform-specific deployment guides: [macOS](docs/MACOS_DEPLOYMENT.md) or [Windows](docs/WINDOWS_DEPLOYMENT.md)
3. Contact your IT security team

---

**Ready to deploy?** This production-ready solution provides complete SAML enforcement with enterprise-grade security. Implementation time: 30 minutes. No infrastructure changes required.

*For detailed technical information, architectural decisions, and advanced configurations, see the [full documentation](docs/).*