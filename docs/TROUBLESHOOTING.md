# Troubleshooting Guide

## Quick Fixes for Common Issues

### "Unable to connect to our servers" (Error 181)
```bash
# Restart the daemon
sudo ./scripts/daemon_manager.sh restart
```

### SSL Certificate Errors
```bash
# ERR_SSL_UNRECOGNIZED_NAME_ALERT or ERR_SSL_PROTOCOL_ERROR
sudo ./scripts/daemon_manager.sh trust-cert
```

### Port 443 Already in Use

**Important**: The daemon MUST listen on port 443 for HTTPS interception to work properly. Browsers always connect to port 443 for HTTPS URLs.

```bash
# Find what's using port 443
sudo lsof -i :443  # macOS/Linux
netstat -ano | findstr :443  # Windows

# The daemon_manager script handles basic conflicts
sudo ./scripts/daemon_manager.sh restart
```

**For persistent port conflicts or enterprise environments**, see the comprehensive port forwarding and reverse proxy solutions in the deployment guides:
- **macOS**: See [MACOS_DEPLOYMENT.md](MACOS_DEPLOYMENT.md#port-443-already-in-use) for 6 different resolution options including nginx, Apache, pfctl, socat, Caddy, and HAProxy configurations
- **Windows**: See [WINDOWS_DEPLOYMENT.md](WINDOWS_DEPLOYMENT.md#port-443-already-in-use) for IIS ARR, Apache, nginx, netsh port proxy, and SNI-based routing solutions

Administrators can configure the daemon to listen on any available port (8443, 9443, 10443, etc.) when using proper reverse proxy or port forwarding configurations.

### Certificate Missing or Expired
```bash
# Regenerate and trust certificates
sudo ./scripts/daemon_manager.sh generate-cert
sudo ./scripts/daemon_manager.sh trust-cert
```

## Platform-Specific Troubleshooting

### macOS

#### Certificate Trust Issues

**Problem**: Certificate exists but isn't trusted for SSL

**Solution**:
```bash
# Fix certificate trust
sudo ./scripts/daemon_manager.sh trust-cert

# This runs:
# 1. Removes old certificate from keychain
# 2. Generates new cert if missing
# 3. Adds certificate with -r trustRoot flag for FULL SSL trust

# Verify trust (should show "0 trust settings" which means fully trusted)
security dump-trust-settings -d
```

**Important**: `"0 trust settings"` is CORRECT - it means "trusted for everything" with no restrictions.

#### Connection Refused

```bash
# Check if daemon is running
sudo ./scripts/daemon_manager.sh status

# Check port binding
sudo lsof -i :443

# Check process
ps aux | grep auth_router_final

# Restart if needed
sudo ./scripts/daemon_manager.sh restart
```

#### DNS Not Resolving

```bash
# Verify hosts entries
grep postman /etc/hosts

# Should show:
# 127.0.0.1 identity.getpostman.com
# 127.0.0.1 identity.postman.co
# 127.0.0.1 id.gw.postman.com

# Flush DNS cache
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# Test resolution
ping identity.getpostman.com
```

### Windows

#### Certificate Trust Issues

**Problem**: Certificate not trusted by Windows

**Solution**:
```powershell
# Run as Administrator
.\scripts\daemon_manager.ps1 trust-cert

# Manually import if needed
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import("ssl\cert.pem")
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()
```

#### Connection Refused

```powershell
# Check service status
.\scripts\daemon_manager.ps1 status

# Check port binding
netstat -an | findstr :443

# Check Windows Firewall
New-NetFirewallRule -DisplayName "Postman Auth Daemon" `
  -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

# Restart service
.\scripts\daemon_manager.ps1 restart
```

#### DNS Not Resolving

```powershell
# Check hosts file
type C:\Windows\System32\drivers\etc\hosts | findstr postman

# Flush DNS cache
ipconfig /flushdns

# Test resolution
nslookup identity.getpostman.com
ping identity.getpostman.com
```

### Linux

#### Permission Issues

```bash
# Ensure running as root
sudo ./scripts/daemon_manager.sh start

# Check file permissions
ls -la /etc/hosts
ls -la ssl/

# Fix permissions if needed
sudo chmod 644 /etc/hosts
sudo chmod 600 ssl/key.pem
sudo chmod 644 ssl/cert.pem
```

#### SELinux/AppArmor Issues

```bash
# Check SELinux status
getenforce

# Temporarily disable for testing (not for production)
sudo setenforce 0

# Create SELinux policy for daemon
sudo audit2allow -a -M postman_auth
sudo semodule -i postman_auth.pp

# For AppArmor
sudo aa-complain /usr/bin/python3
```

## Authentication Issues

### Session Not Persisting

**Symptoms**: Have to re-authenticate repeatedly

**Solutions**:

1. **Check browser cookies**:
   - Open DevTools > Application > Cookies
   - Look for Postman session cookies
   - Verify they're not being blocked

2. **Clear all sessions and retry**:
   ```bash
   # macOS
   ./tools/clear_mac_sessions.sh
   
   # Windows
   .\tools\clear_win_sessions.ps1
   ```

3. **Verify IdP configuration**:
   - Ensure callback URL is correct
   - Check SAML response is returning to correct domain

### Redirect Loop

**Symptoms**: Browser keeps redirecting without completing auth

**Solutions**:

1. **Check state machine**:
   ```bash
   # View current state
   curl -k https://localhost:443/health | jq .current_state
   ```

2. **Reset daemon state**:
   ```bash
   sudo ./scripts/daemon_manager.sh restart
   ```

3. **Check OAuth timeout**:
   - Ensure `oauth_timeout_seconds` is at least 30
   - Never set below 30 seconds

### 401 Unauthorized Errors

**Symptoms**: Authentication completes but Postman shows 401

**Causes**:
- OAuth continuation flow was interrupted
- State machine in wrong state during OAuth
- Certificate validation failed

**Solutions**:

1. **Check logs for OAuth disruption**:
   ```bash
   grep "OAUTH_CONTINUATION" /var/log/postman-auth.log
   ```

2. **Ensure daemon doesn't intercept during OAuth**:
   ```bash
   # Check for interception during OAuth
   grep "intercepting during OAUTH" /var/log/postman-auth.log
   ```

3. **Restart and retry**:
   ```bash
   sudo ./scripts/daemon_manager.sh restart
   ```

## Performance Issues

### High CPU Usage

**Check for busy loops**:
```bash
# Monitor CPU usage
top -p $(pgrep -f saml_enforcer.py)

# Check log spam
tail -f /var/log/postman-auth.log | grep -c "DEBUG"

# Reduce log level if needed
# In config.json: "log_level": "WARNING"
```

### Memory Leaks

**Monitor memory usage**:
```bash
# Check memory over time
while true; do
  ps aux | grep auth_router_final | grep -v grep
  sleep 60
done

# Force restart if growing
sudo ./scripts/daemon_manager.sh restart
```

### Slow Response Times

**Check DNS resolution**:
```bash
# Test DNS resolver
time nslookup identity.getpostman.com 8.8.8.8

# Check cache hits
grep "Resolved.*via cache" /var/log/postman-auth.log | wc -l
```

## Debugging Techniques

### Enable Debug Logging

```json
// config/config.json
{
  "advanced": {
    "log_level": "DEBUG"
  }
}
```

### Monitor Real-Time Logs

```bash
# Follow logs in real-time
tail -f /var/log/postman-auth.log

# Filter for errors only
tail -f /var/log/postman-auth.log | grep ERROR

# Watch state transitions
tail -f /var/log/postman-auth.log | grep "State transition"
```

### Test Individual Components

#### Test Health Endpoint
```bash
curl -k https://localhost:443/health | jq .
```

#### Test DNS Resolution
```python
python3 -c "
from src.auth_router_final import DNSResolver
resolver = DNSResolver()
print(resolver.resolve('identity.getpostman.com'))
"
```

#### Test State Machine
```python
python3 -c "
from src.auth_router_final import AuthStateMachine, AuthState
sm = AuthStateMachine()
print(f'Initial state: {sm.current_state}')
sm.transition_to(AuthState.AUTH_INIT)
print(f'After transition: {sm.current_state}')
"
```

### Network Debugging

#### Capture Traffic
```bash
# Capture HTTPS traffic (requires root)
sudo tcpdump -i lo0 -w postman.pcap port 443

# Analyze with Wireshark
wireshark postman.pcap
```

#### Test Upstream Connectivity
```bash
# Test direct connection to Postman
curl -I https://identity.getpostman.com/login

# Test via daemon
curl -I -H "Host: identity.getpostman.com" https://localhost/login
```

## Log Analysis

### Common Log Patterns

#### Successful Authentication
```
INFO - State transition: IDLE -> AUTH_INIT
INFO - Browser flow detected - redirecting to SAML with team
INFO - State transition: AUTH_INIT -> SAML_FLOW
INFO - OAuth flow reached id.gw.postman.com
INFO - State transition: SAML_FLOW -> OAUTH_CONTINUATION
INFO - Authentication completed successfully
INFO - State transition: OAUTH_CONTINUATION -> IDLE
```

#### Bypass Attempt
```
WARNING - BYPASS ATTEMPT DETECTED: intent=switch-account
WARNING - Bypass attempt detected: auth_challenge without prior /client/login
INFO - Stripped potentially dangerous parameters: {'intent', 'target_team'}
```

#### Certificate Issues
```
ERROR - SSL certificate or key not found
ERROR - [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed
ERROR - SNI proxy error: [SSL: TLSV1_ALERT_UNRECOGNIZED_NAME]
```

### Log Aggregation Queries

#### Splunk
```spl
index=security source="/var/log/postman-auth.log" 
| stats count by severity
| where severity="ERROR" OR severity="WARNING"
```

#### Elasticsearch
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"source": "postman-auth"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ],
      "should": [
        {"match": {"level": "ERROR"}},
        {"match": {"level": "WARNING"}}
      ]
    }
  }
}
```

## Recovery Procedures

### Complete Reset

```bash
# Stop everything
sudo ./scripts/daemon_manager.sh stop

# Clear all configurations
sudo ./scripts/daemon_manager.sh cleanup

# Remove all sessions
./tools/clear_mac_sessions.sh  # or clear_win_sessions.ps1

# Reinstall from scratch
sudo ./scripts/daemon_manager.sh setup
```

### Partial Recovery

```bash
# Just fix certificates
sudo ./scripts/daemon_manager.sh generate-cert
sudo ./scripts/daemon_manager.sh trust-cert

# Just fix hosts file
sudo ./scripts/daemon_manager.sh fix-hosts

# Just restart daemon
sudo ./scripts/daemon_manager.sh restart
```

## Getting Help

### Diagnostic Information to Collect

When reporting issues, collect:

1. **System information**:
   ```bash
   uname -a
   python3 --version
   ```

2. **Daemon status**:
   ```bash
   sudo ./scripts/daemon_manager.sh status
   curl -k https://localhost:443/health
   ```

3. **Recent logs**:
   ```bash
   tail -n 100 /var/log/postman-auth.log
   ```

4. **Configuration** (sanitized):
   ```bash
   cat config/config.json | sed 's/"[a-zA-Z0-9_-]*tenant[a-zA-Z0-9_-]*":.*/REDACTED/g'
   ```

5. **Network state**:
   ```bash
   grep postman /etc/hosts
   netstat -an | grep 443
   ```

### Support Channels

- Internal IT Help Desk
- Enterprise Security Team
- Postman Enterprise Support (for Postman-specific issues)
- MDM Vendor Support (for deployment issues)