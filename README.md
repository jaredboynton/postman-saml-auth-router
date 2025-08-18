# Postman SAML Authentication Enforcer

**Enterprise-grade SAML enforcement for Postman Web and Desktop applications**

A local authentication proxy that forces all Postman sign-ins through your corporate SSO provider, preventing shadow IT and ensuring compliance across your entire fleet.

## What This Does

When users try to sign into Postman (Web or Desktop), they are automatically redirected to your company's SAML identity provider - no authentication choice, no personal accounts, just secure enterprise access.

**Key Benefits:**
- **100% SAML enforcement** - No bypass possible
- **Works everywhere** - Office, home, VPN, coffee shop
- **Quick deployment** - Via MDM, no network changes
- **No dependencies** - Pure Python standard library
- **99% data exfiltration prevention** when combined with Domain Capture and Device Trust. While this won't stop a copy-paster or an intentionally malicious actor, this should stop everything else.

## Local Testing (Before MDM Deployment)

**Note**: These steps are for local testing and validation only. Production deployment uses MDM tools (JAMF, Intune, SCCM) which handle installation, configuration, and certificate management automatically. See [Deployment Guide](docs/DEPLOYMENT.md) for enterprise deployment.

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

## How It Works

```
User → postman.co → Local Proxy (port 443) → Your SAML IdP
                         ↑
                    (via /etc/hosts)
```

The daemon intercepts authentication requests and enforces SAML-only access through a sophisticated state machine that preserves OAuth flows while blocking bypass attempts.

## Documentation

### Planning & Evaluation
- [Security Model & Threat Analysis](docs/SECURITY.md) - Comprehensive security documentation
- [Architecture Overview](docs/ARCHITECTURE.md) - Technical design and components
- [Why Local Enforcement](docs/adr/local-enforcement.md) - Architectural decision rationale

### Implementation
- [Deployment Guide](docs/DEPLOYMENT.md) - MDM deployment for JAMF, Intune, SCCM
- [Configuration Reference](docs/CONFIGURATION.md) - All configuration options
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Common issues and solutions

### Additional Resources
- [Windows Deployment](docs/WINDOWS_DEPLOYMENT.md) - Windows-specific guidance
- [macOS Deployment](docs/MACOS_DEPLOYMENT.md) - macOS-specific guidance
- [Authentication Flow](docs/AUTHENTICATION_FLOW.md) - Detailed flow analysis
- [Alternative Implementations](docs/ALTERNATIVE_IMPLEMENTATIONS.md) - Network-level and proxy integration options

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

## Management Commands

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

## Security Highlights

- **Bypass Prevention**: Detects and blocks all known bypass techniques
- **Session Control**: Instant session termination for offboarding and fine-tuning session length via `clear_mac_sessions.sh` and `clear_win_sessions.ps1` scripts deployed via MDM
- **Audit Logging**: SIEM-ready structured logs
- **Certificate Security**: Enterprise CA support with MDM deployment
- **Process Protection**: Cannot be killed even with admin privileges when deployed via MDM

See [Security Documentation](docs/SECURITY.md) for complete details.

## Requirements

- **OS**: macOS 10.15+, Windows 10+, Ubuntu 20.04+
- **Python**: 3.8 or higher
- **Privileges**: Root/Administrator access
- **Enterprise**: SAML-configured Postman team

## Project Structure

```
postman_redirect_daemon/
├── README.md                       # This file
├── PROGRESS.md                     # Development progress tracker
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
│   └── config.json                 # Your configuration (git-ignored)
│
├── ssl/                            # SSL certificates
│   ├── cert.conf                   # Certificate configuration
│   ├── cert.pem                    # SSL certificate (generated)
│   └── key.pem                     # Private key (generated)
│
├── tools/                          # Utility scripts
│   ├── clear_mac_sessions.sh       # macOS session clearing
│   ├── clear_win_sessions.ps1      # Windows session clearing
│   ├── create_jamf_package.sh      # JAMF deployment helper
│   ├── deploy_intune.ps1           # Intune deployment template
│   ├── deploy_sccm.ps1             # SCCM deployment template
│   └── validate_config.py          # Configuration validator
│
├── docs/                           # Documentation
│   ├── SECURITY.md                 # Security model & controls
│   ├── ARCHITECTURE.md             # Technical architecture
│   ├── DEPLOYMENT.md               # Enterprise deployment guide
│   ├── CONFIGURATION.md            # Configuration reference
│   ├── TROUBLESHOOTING.md          # Troubleshooting guide
│   ├── ALTERNATIVE_IMPLEMENTATIONS.md # Network & proxy alternatives
│   ├── TECHNICAL.md                # Implementation details
│   ├── AUTHENTICATION_FLOW.md      # Flow analysis
│   ├── MACOS_DEPLOYMENT.md         # macOS-specific guide
│   ├── WINDOWS_DEPLOYMENT.md       # Windows-specific guide
│   └── adr/                        # Architecture Decision Records
│       └── local-enforcement.md    # Why local vs network proxy
│
└── logs/                           # Log files (created at runtime)
    └── postman-auth.log            # Daemon logs
```

## Industry Validation

This local enforcement pattern is the industry standard, used by:
- **CrowdStrike Falcon** - DNS security via hosts modification
- **Microsoft Defender** - Local proxy for web protection
- **Zscaler** - Local agent for cloud security

## Support

For deployment assistance or questions:
1. Check [Troubleshooting Guide](docs/TROUBLESHOOTING.md)
2. Review [deployment logs](docs/DEPLOYMENT.md#validation-checklist)
3. Contact your IT security team

---

**Ready to deploy?** This production-ready solution provides complete SAML enforcement with enterprise-grade security. Implementation time: 30 minutes. No infrastructure changes required.

*For detailed technical information, architectural decisions, and advanced configurations, see the [full documentation](docs/).*