# Architecture Documentation

## System Architecture Overview

The Postman SAML Authentication Enforcer is a local HTTPS proxy that intercepts authentication requests and enforces SAML-only authentication through your corporate identity provider.

### High-Level Flow

```
Browser/Desktop App → identity.getpostman.com
         ↓
[Static hosts file redirects to 127.0.0.1]
         ↓
Local Authentication Daemon (port 443)
         ↓
Desktop Detection:
   ├─ Desktop: /client/login → Sets desktop_flow_initiated flag
   │           ↓
   │           Server generates auth_challenge
   │           ↓
   │           Redirects to /login?auth_challenge=xxx
   │           ↓
   │           Daemon validates flag exists (prevents replay)
   │           ↓
   │           Preserves auth_challenge through SAML flow
   │
   └─ Web: Direct /login request (no auth_challenge)
         ↓
State Machine Tracks Authentication Flow
   ├─ IDLE → AUTH_INIT → SAML_FLOW
   ├─ OAUTH_CONTINUATION (30s timeout, never intercept)
   └─ Reset to IDLE after timeout or completion
         ↓
Intercept at specific points only:
   ├─ /login → Redirect to Corporate IDP (SAML)
   │   └─ Desktop: Includes auth_challenge parameter
   │   └─ Web: Includes continue URL parameter
   └─ OAuth /continue → Pass through to real servers (SNI)
         ↓
Session Return:
   ├─ Desktop: OAuth callback includes auth_challenge
   │           → Postman validates and opens Desktop app
   │           → Desktop app receives session token
   │
   └─ Web: OAuth callback sets browser cookies
           → User redirected to Postman web app
```

## Core Components

### 1. Authentication Daemon (`auth_router_final.py`)

The main daemon that listens on port 443 and handles all intercepted requests.

**Key responsibilities:**
- SSL/TLS termination with self-signed or enterprise certificates
- Request interception and routing decisions
- SAML redirect generation
- Upstream proxy with SNI handling

### 2. State Machine (`AuthStateMachine`)

Tracks authentication flow to ensure proper interception timing.

#### State Transitions

```
┌─────┐    /client/login or /login  ┌───────────┐
│IDLE │ ──────────────────────────→ │AUTH_INIT  │
└─────┘                             └───────────┘
   ↑                                       │
   │                                       │ intercept /login
   │ timeout (30s)                         │ redirect to SAML
   │                                       ↓
   │                                ┌─────────────┐
   │                                │SAML_FLOW    │
   │                                └─────────────┘
   │                                       │
   │                                       │ /continue detected
   │                                       ↓
   │                                ┌──────────────────┐
   │                                │OAUTH_CONTINUATION│
   │                                └──────────────────┘
   │                                       │
   │ success or timeout (30s)              │
   └───────────────────────────────────────┘
```

**Critical Rules:**
- NEVER intercept during `OAUTH_CONTINUATION` state (breaks auth chain)
- OAuth timeout (30s) prevents stuck sessions
- `identity.postman.com` hosts OAuth state validation
- Breaking OAuth chain causes 401 authentication errors

### 3. DNS Resolver (`DNSResolver`)

Resolves real IP addresses to avoid proxy loops when hosts file points domains to localhost.

**Features:**
- Uses external DNS (8.8.8.8 by default) to get real IPs
- Caches resolved addresses for performance
- Fallback to hardcoded IPs if DNS fails
- Thread-safe operation

### 4. Request Handler (`PostmanAuthHandler`)

HTTP request handler that processes all incoming requests.

**Request Processing Flow:**
1. Health check bypass (`/health` endpoint)
2. Bypass detection (intent=switch-account, fake auth_challenge)
3. State machine consultation (should intercept?)
4. SAML redirect if intercepting
5. Proxy to upstream if not intercepting

## Authentication Flows

### Web Browser Flow

1. User navigates to `postman.co`
2. Redirected to `identity.getpostman.com/login`
3. Request intercepted by daemon (via hosts file)
4. State: `IDLE` → `AUTH_INIT`
5. Daemon redirects to SAML IdP
6. State: `AUTH_INIT` → `SAML_FLOW`
7. User authenticates with IdP
8. IdP redirects back to Postman
9. OAuth continuation begins
10. State: `SAML_FLOW` → `OAUTH_CONTINUATION`
11. Daemon passes through all requests
12. Authentication completes
13. State: `OAUTH_CONTINUATION` → `IDLE`

### Desktop Application Flow

**Critical: The Desktop flow uses a two-step authentication process with auth_challenge validation**

1. **Desktop app initiates authentication:**
   - User clicks "Sign In" in Postman Desktop
   - Desktop app opens browser to `identity.getpostman.com/client/login`
   
2. **Daemon tracks Desktop flow initiation:**
   ```python
   if "/client" in path:
       self.session_data['desktop_flow_initiated'] = True
       return False  # Pass through to real server
   ```
   
3. **Postman server generates auth_challenge:**
   - Server receives `/client/login` request
   - Generates unique `auth_challenge` token
   - Redirects to `/login?auth_challenge=xyz123...`
   
4. **Daemon validates auth_challenge:**
   ```python
   if 'auth_challenge' in query_params:
       if not self.state_machine.session_data.get('desktop_flow_initiated'):
           # BLOCKED: Replay attack attempt
           return True
   ```
   
5. **SAML redirect preserves auth_challenge:**
   - Daemon intercepts `/login?auth_challenge=xyz123...`
   - Validates `desktop_flow_initiated` flag exists
   - Redirects to SAML IdP with auth_challenge preserved
   - State: `IDLE` → `AUTH_INIT` → `SAML_FLOW`
   
6. **User authenticates with IdP:**
   - Standard SAML authentication flow
   - IdP redirects back to Postman with SAML response
   
7. **OAuth continuation with auth_challenge:**
   - Postman processes SAML response
   - Begins OAuth flow at `/continue`
   - State: `SAML_FLOW` → `OAUTH_CONTINUATION`
   - Daemon passes through all requests (never intercepts)
   - Auth_challenge included in OAuth callback
   
8. **Session delivered to Desktop app:**
   - OAuth completes with `auth_challenge` parameter
   - Postman server validates auth_challenge
   - Server triggers deep link: `postman://auth/callback?token=...`
   - Desktop app receives and stores session token
   - User is logged into Desktop application

**Desktop vs Web Detection:**
- **Desktop**: Two-step process with `/client/login` → `/login?auth_challenge=...`
- **Web**: Direct `/login` request without auth_challenge
- **Key difference**: Only Desktop flow has `desktop_flow_initiated` flag and auth_challenge
- **Security**: Auth_challenge without prior `/client/login` is blocked as replay attack

## Proxy Architecture

### SNI (Server Name Indication) Handling

When proxying to upstream servers behind Cloudflare, proper SNI is critical:

```python
def _proxy_with_sni(self, host: str, upstream_ip: str, ...):
    # Create raw socket to resolved IP
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.connect((upstream_ip, 443))
    
    # Wrap with SSL, setting SNI to original hostname
    # CRITICAL: server_hostname sets SNI for Cloudflare routing
    ssl_socket = context.wrap_socket(raw_socket, server_hostname=host)
```

Without proper SNI, Cloudflare returns 525 SSL handshake failed errors.

### Proxy Methods

**`_proxy_with_sni()`** - For intercepted domains needing SNI
- Resolves domain to real IP
- Creates socket connection to IP
- Wraps with SSL using original hostname for SNI
- Handles raw HTTP request/response

**`_proxy_direct()`** - For non-intercepted domains
- Uses standard HTTPSConnection
- No special SNI handling needed
- Simpler but less control

## Security Architecture

### Certificate Handling

**Development:**
- Self-signed certificate with SAN entries for all Postman domains
- Must be explicitly trusted in system keychain
- Generated via `generate_certs.sh` script

**Production:**
- Enterprise CA-signed certificates
- Deployed via MDM certificate profiles
- Automatic renewal through MDM
- Certificate pinning optional

### Bypass Prevention Layers

1. **Parameter Sanitization** (`_sanitize_login_params`)
   - Removes dangerous parameters
   - Validates continue URLs
   - Preserves only safe parameters

2. **Auth Challenge Validation** (`_is_bypass_attempt`)
   - Tracks Desktop flow initiation
   - Blocks replay attacks
   - Validates sequence integrity

3. **State Machine Enforcement** (`should_intercept`)
   - Controls when interception occurs
   - Prevents OAuth flow disruption
   - Enforces timeout policies

## Performance Considerations

### Caching
- DNS results cached to avoid repeated lookups
- State transitions tracked in memory
- No external database dependencies

### Timeouts
- General session timeout: 30 seconds (configurable)
- OAuth continuation timeout: 30 seconds (critical)
- Network timeouts: 30 seconds default

### Resource Usage
- Single-threaded HTTP server (sufficient for local proxy)
- Minimal memory footprint (~10MB)
- No external dependencies (pure Python stdlib)

## Configuration Architecture

### Configuration Hierarchy

```json
{
  "postman_team_name": "team-name",     // Required
  "idp_config": {                       // Required
    "idp_type": "okta|azure|ping|generic",
    "tenant_id": "...",                 // IdP-specific
    "connection_id": "..."               // IdP-specific
  },
  "advanced": {                          // Optional
    "dns_server": "8.8.8.8",
    "timeout_seconds": 30,
    "oauth_timeout_seconds": 30,
    "listen_port": 443,
    "allow_insecure_upstream": false
  }
}
```

### IdP Integration

**Supported IdPs:**
- Okta (with tenant_id)
- Azure AD (with tenant_id)
- Ping Identity (with connection_id)
- Generic SAML (fallback)

**URL Generation:**
- IdP-specific URL patterns
- Team name injection
- Parameter preservation (auth_challenge, continue)

## Monitoring & Observability

### Health Endpoint

`GET /health` returns:
```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "current_state": "idle",
  "metrics": {
    "auth_attempts": 100,
    "saml_redirects": 95,
    "bypass_attempts": 2,
    "successful_auths": 90,
    "failed_auths": 5
  },
  "config": {
    "team": "your-team",
    "idp_type": "okta"
  }
}
```

### Logging Architecture

**Log Levels:**
- INFO: Normal operations, state transitions
- WARNING: Bypass attempts, timeouts
- ERROR: Connection failures, SSL errors
- DEBUG: Detailed request/response data

**Log Rotation:**
- RotatingFileHandler with 10MB max size
- 5 backup files by default
- Falls back to console if file unavailable

## Failure Modes & Recovery

### Common Failure Scenarios

1. **Certificate Expiration**
   - Health endpoint reports unhealthy
   - Regenerate certificates
   - Restart daemon

2. **IdP Outage**
   - Existing sessions continue working (90-day lifetime)
   - New authentications fail with clear error
   - No daemon changes needed

3. **Port Conflict**
   - Daemon fails to start
   - Check for other processes on port 443
   - Kill conflicting process or change port

4. **DNS Resolution Failure**
   - Falls back to hardcoded IPs
   - May cause issues with IP changes
   - Update fallback IPs in config

### Graceful Degradation

- Timeouts prevent infinite hangs
- State machine resets on errors
- Bypass attempts logged but don't crash daemon
- Health endpoint remains accessible even during auth failures