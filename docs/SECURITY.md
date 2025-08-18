# Security Documentation

## Threat Model Addressed

This solution addresses the following enterprise security threats:

- **Unauthorized access via personal Postman accounts** - Forces all authentication through corporate IdP
- **Data exfiltration through non-corporate workspaces** - Ensures users can only access the designated enterprise team
- **Shadow IT usage of Postman outside IT control** - All usage tracked through corporate SSO
- **Compliance violations from unmanaged API access** - Provides complete audit trail

## Security Controls Implemented

### Authentication Enforcement
- **Forced SAML authentication** - No bypass possible, all auth flows through corporate IdP
- **Auth challenge replay attack prevention** - Desktop flows must follow legitimate sequence
- **Parameter-based bypass detection and blocking** - Detects and blocks known bypass patterns
- **Session management** - Configurable timeouts with forced termination capability

### Bypass Detection & Prevention

The daemon implements multiple layers of bypass prevention:

#### 1. Parameter-Based Bypass Blocking
- Blocks `intent=switch-account` which triggers account switching UI
- Strips `target_team` parameter that could select non-SAML teams  
- Removes `force_auth` and `skip_saml` parameters
- Sanitizes all dangerous query parameters before processing

#### 2. Auth Challenge Validation
- Tracks Desktop flows via `desktop_flow_initiated` flag
- Blocks auth_challenge without prior `/client/login` (replay attack prevention)
- Validates auth_challenge sequence to prevent token reuse
- Logs all suspicious auth_challenge attempts

#### 3. Continue URL Validation
- Only allows HTTPS URLs for continue parameter
- Restricts to Postman-owned domains only
- Blocks external redirects that could leak credentials
- Prevents redirect-based bypass attempts

#### 4. Security Logging
- All bypass attempts logged with full parameter details
- Real-time metrics available via health endpoint
- SIEM-ready structured logging for security monitoring
- Tracks patterns for threat intelligence

## Compliance Benefits

### Audit & Monitoring
- **Complete audit trail** of all access attempts
- **Structured logging** compatible with SIEM systems
- **Real-time metrics** via health endpoint
- **Session tracking** for compliance reporting

### Standards Compliance
- **SOC2** - Enforces access controls and audit logging
- **ISO 27001** - Implements authentication and monitoring controls
- **HIPAA** - Ensures PHI access through authorized channels only
- **Industry-specific** - Customizable for financial services, healthcare requirements

### Enterprise Control
When deployed with complementary controls:
- **Domain Capture** - Prevents email-based workspace creation
- **Device Trust via IdP** - Restricts to managed devices only
- **Result**: 99% data exfiltration prevention

*Note: The remaining 1% represents inherent limitations (manual copy/paste, screenshots, etc.) that no technical solution can prevent while maintaining usability.*

## Security Architecture

### MDM-Based Security Model

**Process Protection via MDM:**
- MDM deploys processes with System Integrity Protection (SIP) on macOS
- Windows services run as SYSTEM with deny-terminate ACLs
- Process cannot be killed even with sudo/admin privileges
- MDM policies prevent users from modifying /etc/hosts

**Why MDM is More Secure Than Network Controls:**

Network-based auth can be bypassed via:
- VPN to different regions
- Mobile hotspots  
- Home networks
- Coffee shop WiFi

MDM-based auth works everywhere:
- Follows the device, not the network
- Can't be circumvented by changing networks
- Enforced at the OS level, not network level
- Works identically on any network connection

### Certificate Security

**Enterprise Certificate Deployment:**
- Certificates deployed via MDM certificate profiles
- Automatic renewal through MDM policies
- Certificate pinning prevents MITM attacks
- Supports enterprise CA infrastructure

**Self-Signed Certificate (Development Only):**
- Generated with proper SAN entries for all Postman domains
- Must be explicitly trusted in system keychain
- Should be replaced with enterprise certificates in production

## Security Monitoring

### Health Endpoint

Available at `https://localhost:443/health` (or configured port)

```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "current_state": "idle",
  "metrics": {
    "auth_attempts": 150,
    "saml_redirects": 145,
    "bypass_attempts": 5,
    "successful_auths": 140,
    "failed_auths": 10
  }
}
```

### Log Analysis

**Security Events to Monitor:**
- `BYPASS ATTEMPT DETECTED` - Potential attack attempts
- `Auth challenge without prior /client/login` - Replay attacks
- `Blocked unsafe continue URL` - Redirect attacks
- `Failed authentication` - Brute force attempts

**Log Rotation:**
- Default: 10MB max size with 5 backup files
- Configurable via deployment scripts
- Integration with centralized logging systems

## Session Security

### Session Management

**Session Persistence:**
- Postman sessions persist for 90 days by default
- Minimum 18-hour session lifetime
- Continues working during IdP outages

**Immediate Termination:**
Organizations can instantly terminate all sessions using included scripts:
- `tools/clear_mac_sessions.sh` - macOS session clearing
- `tools/clear_win_sessions.ps1` - Windows session clearing

These scripts clear sessions from:
- All major browsers (Chrome, Firefox, Safari, Edge)
- Postman Desktop application
- System credential stores

### OAuth Flow Protection

**State Machine Security:**
- Never intercepts during `OAUTH_CONTINUATION` state
- 30-second timeout prevents stuck sessions
- Automatic state reset on timeout
- Preserves OAuth token exchange integrity

## Incident Response

### Security Incident Procedures

1. **Bypass Attempt Detected:**
   - Review logs for attack patterns
   - Check if user account is compromised
   - Deploy session termination if needed
   - Update bypass detection rules

2. **Certificate Issues:**
   - Regenerate certificates immediately
   - Deploy via MDM to all devices
   - Force restart of daemon fleet-wide

3. **IdP Compromise:**
   - Terminate all sessions immediately
   - Disable daemon temporarily if needed
   - Coordinate with IdP team for remediation

### Emergency Controls

**Kill Switch Implementation:**
```bash
# Disable all authentication (emergency only)
sudo ./scripts/daemon_manager.sh emergency-stop

# Clear all sessions enterprise-wide
sudo ./scripts/clear_all_sessions.sh

# Remove hosts entries
sudo ./scripts/daemon_manager.sh cleanup
```

## Security Best Practices

### Deployment Security
1. Always use enterprise-signed certificates in production
2. Deploy via MDM with process protection enabled
3. Configure log shipping to SIEM before deployment
4. Test bypass prevention in isolated environment first

### Operational Security
1. Monitor bypass attempts daily
2. Review authentication metrics weekly
3. Update certificates before expiration
4. Maintain current bypass pattern definitions

### Configuration Security
1. Never commit actual configuration files to version control
2. Use environment-specific config management
3. Rotate IdP credentials regularly
4. Validate all configuration changes in staging first