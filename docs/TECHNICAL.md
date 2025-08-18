# Technical Implementation Guide

## Overview

The Postman SAML Enforcement Daemon intercepts authentication requests and enforces SAML-only authentication for enterprise environments. It operates as a transparent HTTPS proxy using Python's standard library with zero external dependencies.

## Core Architecture

### State Machine Design

The daemon uses a 6-state authentication flow tracker:

```
IDLE → AUTH_INIT → LOGIN_REDIRECT → SAML_FLOW → OAUTH_CONTINUATION → COMPLETE
```

**Why:** This prevents intercepting OAuth continuation requests which must reach real servers for state validation. Breaking the OAuth chain causes 401 errors.

### Hosts File Management - Two Approaches

#### 1. Static Hosts (DEFAULT - Recommended)

The daemon uses static `/etc/hosts` entries by default:

```bash
127.0.0.1 identity.getpostman.com
127.0.0.1 identity.postman.co
```

**Advantages:**
- Simple and reliable
- No runtime modifications needed
- Works with all MDM systems
- Minimal attack surface

**How it works:**
- Fixed entries redirect domains to daemon
- Daemon proxies non-intercepted requests to real servers
- Uses DNS resolution with SNI for proper SSL handling

#### 2. Dynamic Hosts (Optional via --dynamic-hosts flag)

Advanced mode that modifies `/etc/hosts` based on authentication state:

```bash
sudo python3 auth_router_final.py --dynamic-hosts
```

**Advantages:**
- Precise control over interception timing
- Can completely remove entries during OAuth flow
- Useful for debugging authentication issues

**How it works:**
- Adds entries when authentication starts
- Removes entries during OAuth continuation
- Restores entries after completion

**Why both exist:** Static is simpler for production deployments. Dynamic provides granular control for complex environments or troubleshooting.

## Critical Implementation Details

### DNS Resolution with SNI

The daemon uses a hybrid approach to resolve real IPs and bypass `/etc/hosts`:

**Resolution Methods (in order):**
1. **nslookup** (primary) - Enterprise-friendly, works through corporate firewalls
2. **DNS-over-HTTPS** (fallback) - When nslookup fails or is unavailable
3. **Configured fallback IPs** (last resort) - For complete DNS failure

```python
# Get real IP despite hosts file using hybrid approach
real_ip = dns_resolver.resolve('identity.getpostman.com')  # Returns 104.18.36.161

# Connect with proper SNI for Cloudflare
ssl_socket = context.wrap_socket(raw_socket, server_hostname='identity.getpostman.com')
```

**Configuration:**
```json
{
  "advanced": {
    "dns_resolution_method": "auto",  // "auto", "nslookup", or "doh"
    "dns_server": "8.8.8.8",
    "dns_fallback_ips": {
      "identity.getpostman.com": "104.18.36.161"
    }
  }
}
```

**Enterprise Considerations:**
- **nslookup** is universally available and firewall-friendly
- **DNS-over-HTTPS** may be blocked by corporate security policies
- **Fallback IPs** ensure service continuity during DNS outages

**Why SNI matters:** Cloudflare requires correct Server Name Indication (SNI) to route requests. Without this, connections fail with SSL errors.

### OAuth Continuation Protection

The daemon NEVER intercepts `/continue` paths:

```python
if self.current_state == AuthState.OAUTH_CONTINUATION:
    # 30-second timeout prevents stuck sessions
    if (datetime.now() - self.state_entered_at).seconds > 30:
        self.current_state = AuthState.IDLE
    return False  # Never intercept
```

**Why 30 seconds:** Typical OAuth flows complete in 5-10 seconds. 30 seconds allows for slow networks while preventing indefinitely stuck sessions.

### Domains and Interception Rules

**Always Intercept:**
- `identity.getpostman.com/login` - Force SAML redirect
- `identity.getpostman.com/enterprise/login` - Skip team entry

**Never Intercept:**
- `identity.postman.com/*` - OAuth state validation server
- `id.gw.postman.com/*` - Gateway for token exchange
- Any `/continue` path - OAuth state machine

**Why:** `identity.postman.com` (without 'get') hosts OAuth state validation. Intercepting it breaks the authentication chain.

## Authentication Flow Details

### Desktop Flow (with auth_challenge)
1. Desktop opens `/client/login` with `multiLoginToken`
2. Server generates `auth_challenge` 
3. Daemon intercepts `/login?auth_challenge=...`
4. Redirects to `/sso/okta/{tenant}/init` with challenge
5. SAML authentication proceeds
6. OAuth continuation passes through untouched

### Browser Flow (without auth_challenge)
1. User visits `/login` directly
2. Daemon intercepts immediately
3. Redirects to `/sso/okta/{tenant}/init?team=postman`
4. SAML authentication proceeds
5. OAuth continuation passes through untouched

## Certificate Requirements

### Required SAN Entries
```
- DNS:identity.getpostman.com
- DNS:identity.postman.com  
- DNS:identity.postman.co
- DNS:localhost
- IP:127.0.0.1
```

### macOS Trust Configuration
```bash
# MUST use -r trustRoot for SSL trust
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain cert.pem
```

**Why:** Without `-r trustRoot`, certificate exists in keychain but isn't trusted for SSL. This causes ERR_SSL_PROTOCOL_ERROR.

### Windows Trust Configuration
```powershell
# Import to Trusted Root store
certutil -addstore -f "Root" cert.pem
```

## Configuration Options

### Minimal Config (config.json)
```json
{
    "postman_team_name": "your-company-name",
    "idp_type": "okta",
    "okta_tenant_id": "your-okta-tenant-id"
}
```

### Advanced Config
```json
{
    "postman_team_name": "your-company-name",
    "idp_type": "okta",
    "okta_tenant_id": "your-okta-tenant-id",
    "advanced": {
        "timeout_seconds": 30,
        "oauth_timeout_seconds": 30,
        "dns_server": "8.8.8.8",
        "dns_fallback_ips": {
            "identity.getpostman.com": "104.18.36.161",
            "identity.postman.co": "104.18.37.186"
        }
    },
    "listen_port": 443,
    "health_check_port": 8443
}
```

## Operation Modes

### Enforce Mode (Production)
```bash
sudo python3 auth_router_final.py --mode enforce
```
Actively redirects to SAML, prevents bypass attempts.

### Monitor Mode (Testing)
```bash
sudo python3 auth_router_final.py --mode monitor
```
Logs what would be intercepted without actually redirecting.

### Test Mode (Debugging)
```bash
sudo python3 auth_router_final.py --mode test
```
Verbose logging for troubleshooting authentication issues.

## Health Monitoring

### Health Check Endpoint
```bash
curl http://localhost:8443/health
```

Returns:
```json
{
    "status": "healthy",
    "mode": "enforce",
    "current_state": "idle",
    "metrics": {
        "auth_attempts": 145,
        "saml_redirects": 145,
        "bypass_attempts": 0,
        "successful_auths": 143
    }
}
```

## Security Considerations

### Bypass Prevention
- Daemon detects and logs bypass attempts
- Forces SAML even when users try direct login
- Metrics track bypass attempts for security monitoring

### Certificate Pinning Risk
- Future Postman versions may implement certificate pinning
- Would require official Postman certificates
- Monitor Postman updates for security changes

### Electron App Considerations
- Some Electron apps bypass system hosts file
- May use DoH (DNS over HTTPS) 
- May have hardcoded IP addresses
- Current Postman Desktop respects system hosts

## Troubleshooting

### Common Issues

**401 "The request is unauthenticated"**
- OAuth state chain broken
- Check if `identity.postman.com` is in hosts file (shouldn't be)
- Verify OAuth continuation timeout hasn't expired

**ERR_TOO_MANY_REDIRECTS**
- State machine stuck in redirect loop
- Restart daemon to reset state
- Check logs for state transitions

**SSL_PROTOCOL_ERROR**
- Certificate not trusted properly
- Re-run certificate trust command with `-r trustRoot`
- Verify certificate includes all required SANs

**Team entry page still shows**
- Not intercepting `/enterprise/login`
- Check hosts file entries are correct
- Verify daemon is running in enforce mode

## Performance Metrics

- **Zero external dependencies** - Pure Python standard library
- **Startup time** - <1 second
- **Request latency** - <10ms added overhead
- **Memory usage** - ~20MB resident
- **OAuth timeout** - 30 seconds (configurable)
- **Session timeout** - 30 seconds (configurable)

## Files and Paths

### macOS/Linux
- Daemon: `/usr/local/postman-auth/daemon`
- Config: `/etc/postman-auth/config.json`
- Logs: `/var/log/postman-auth.log`
- Certificate: `/etc/postman-auth/cert.pem`

### Windows
- Daemon: `C:\Program Files\PostmanAuth\daemon.exe`
- Config: `C:\ProgramData\PostmanAuth\config.json`
- Logs: `C:\ProgramData\PostmanAuth\logs\`
- Certificate: `C:\ProgramData\PostmanAuth\cert.pfx`

---

*For implementation source code, see `src/auth_router_final.py`*  
*For deployment instructions, see platform-specific guides in `docs/`*