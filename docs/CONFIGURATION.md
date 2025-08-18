# Configuration Guide

## Configuration File Structure

The daemon uses a JSON configuration file located at `config/config.json`. Copy from the template to get started:

```bash
cp config/config.json.template config/config.json
```

## Basic Configuration

### Minimal Configuration

```json
{
  "postman_team_name": "your-team-name",
  "idp_config": {
    "idp_type": "okta",
    "okta_tenant_id": "your-okta-tenant"
  }
}
```

### Full Configuration Example

```json
{
  "postman_team_name": "enterprise-team",
  
  "idp_config": {
    "idp_type": "okta",
    "okta_tenant_id": "dev-12345678",
    "idp_url": "https://dev-12345678.okta.com/app/postman/exk1fxpypwPQQ1A2p5d7/sso/saml",
    "okta_app_id": "0oa1fxpypwPQQ1A2p5d7"
  },
  
  "ssl_cert": "ssl/cert.pem",
  "ssl_key": "ssl/key.pem",
  "listen_port": 443,
  
  "advanced": {
    "dns_server": "8.8.8.8",
    "timeout_seconds": 30,
    "oauth_timeout_seconds": 30,
    "allow_insecure_upstream": false,
    "dns_fallback_ips": {
      "identity.getpostman.com": "104.18.36.161",
      "identity.postman.co": "104.18.37.186"
    }
  }
}
```

## Configuration Parameters

### Required Parameters

#### `postman_team_name`
- **Type**: String
- **Description**: Your Postman Enterprise team name
- **Example**: `"acme-corp"`
- **Note**: This must match your Postman team URL slug

#### `idp_config`
- **Type**: Object
- **Description**: Identity provider configuration
- **Required Fields**:
  - `idp_type`: One of `"okta"`, `"azure"`, `"ping"`, `"generic"`

### IdP-Specific Configuration

#### Okta Configuration

```json
{
  "idp_config": {
    "idp_type": "okta",
    "okta_tenant_id": "dev-12345678",
    "idp_url": "https://dev-12345678.okta.com/app/postman/exk.../sso/saml",
    "okta_app_id": "0oa1fxpypwPQQ1A2p5d7"
  }
}
```

**Required Fields:**
- `okta_tenant_id`: Your Okta tenant identifier
- `idp_url` (optional): Full SAML SSO URL if auto-generation fails
- `okta_app_id` (optional): Okta application ID for advanced configurations

#### Azure AD Configuration

```json
{
  "idp_config": {
    "idp_type": "azure",
    "tenant_id": "12345678-1234-1234-1234-123456789012",
    "app_id": "87654321-4321-4321-4321-210987654321",
    "idp_url": "https://login.microsoftonline.com/.../saml2"
  }
}
```

**Required Fields:**
- `tenant_id`: Azure AD tenant ID (GUID)
- `app_id` (optional): Azure application ID
- `idp_url` (optional): Full SAML endpoint URL

#### Ping Identity Configuration

```json
{
  "idp_config": {
    "idp_type": "ping",
    "connection_id": "con_AbCdEfGhIjKlMnOp",
    "ping_environment": "your-environment",
    "idp_url": "https://auth.pingone.com/.../saml"
  }
}
```

**Required Fields:**
- `connection_id`: Ping connection identifier
- `ping_environment` (optional): Ping environment name
- `idp_url` (optional): Full SAML endpoint URL

#### Generic SAML Configuration

```json
{
  "idp_config": {
    "idp_type": "generic",
    "idp_url": "https://your-idp.com/saml/sso",
    "entity_id": "https://your-idp.com/entity",
    "metadata_url": "https://your-idp.com/metadata.xml"
  }
}
```

**Fields:**
- `idp_url`: Full SAML SSO endpoint
- `entity_id` (optional): SAML entity ID
- `metadata_url` (optional): SAML metadata URL

### Optional Parameters

#### SSL/TLS Configuration

```json
{
  "ssl_cert": "ssl/cert.pem",
  "ssl_key": "ssl/key.pem",
  "ssl_chain": "ssl/chain.pem",
  "listen_port": 443
}
```

- `ssl_cert`: Path to SSL certificate file (default: `"ssl/cert.pem"`)
- `ssl_key`: Path to SSL private key file (default: `"ssl/key.pem"`)
- `ssl_chain`: Path to certificate chain file (optional)
- `listen_port`: Port to listen on (default: `443`)

#### Advanced Configuration

```json
{
  "advanced": {
    "dns_server": "8.8.8.8",
    "timeout_seconds": 30,
    "oauth_timeout_seconds": 30,
    "allow_insecure_upstream": false,
    "health_check_interval": 60,
    "auto_restart_on_failure": true,
    "max_restart_attempts": 3,
    "log_level": "INFO",
    "log_file": "/var/log/postman-auth.log",
    "log_max_bytes": 10485760,
    "log_backup_count": 5
  }
}
```

**DNS Settings:**
- `dns_server`: External DNS server for resolving real IPs (default: `"8.8.8.8"`)
- `dns_fallback_ips`: Hardcoded IPs for critical domains

**Timeout Settings:**
- `timeout_seconds`: General session timeout (default: `30`)
- `oauth_timeout_seconds`: OAuth flow timeout (default: `30`)
- **Warning**: Do not set OAuth timeout below 30 seconds

**Security Settings:**
- `allow_insecure_upstream`: Allow insecure SSL to upstream (default: `false`)
- **Warning**: Only enable for debugging, never in production

**Monitoring Settings:**
- `health_check_interval`: Seconds between health checks
- `auto_restart_on_failure`: Automatically restart on failure
- `max_restart_attempts`: Maximum restart attempts before giving up

**Logging Settings:**
- `log_level`: One of `"DEBUG"`, `"INFO"`, `"WARNING"`, `"ERROR"`
- `log_file`: Path to log file
- `log_max_bytes`: Maximum log file size before rotation
- `log_backup_count`: Number of backup log files to keep

## Environment-Specific Configurations

### Development Environment

```json
{
  "postman_team_name": "dev-team",
  "idp_config": {
    "idp_type": "okta",
    "okta_tenant_id": "dev-tenant"
  },
  "advanced": {
    "log_level": "DEBUG",
    "allow_insecure_upstream": true
  }
}
```

### Staging Environment

```json
{
  "postman_team_name": "staging-team",
  "idp_config": {
    "idp_type": "okta",
    "okta_tenant_id": "staging-tenant"
  },
  "advanced": {
    "log_level": "INFO",
    "health_check_interval": 30
  }
}
```

### Production Environment

```json
{
  "postman_team_name": "production-team",
  "idp_config": {
    "idp_type": "okta",
    "okta_tenant_id": "prod-tenant",
    "backup_idp_url": "https://backup.okta.com/..."
  },
  "advanced": {
    "log_level": "WARNING",
    "auto_restart_on_failure": true,
    "max_restart_attempts": 5,
    "health_check_interval": 60
  }
}
```

## Dynamic Configuration

### Runtime Configuration Updates

The daemon supports configuration reloading without restart:

```bash
# Send HUP signal to reload configuration
sudo kill -HUP $(pgrep -f saml_enforcer.py)
```

### Configuration Validation

Before deploying, validate your configuration:

```python
#!/usr/bin/env python3
import json
import sys

def validate_config(config_path):
    try:
        with open(config_path) as f:
            config = json.load(f)
        
        # Check required fields
        assert 'postman_team_name' in config, "Missing postman_team_name"
        assert 'idp_config' in config, "Missing idp_config"
        assert 'idp_type' in config['idp_config'], "Missing idp_type"
        
        # Validate IdP-specific fields
        idp_type = config['idp_config']['idp_type']
        if idp_type == 'okta':
            assert 'okta_tenant_id' in config['idp_config'], "Missing okta_tenant_id"
        elif idp_type == 'azure':
            assert 'tenant_id' in config['idp_config'], "Missing tenant_id"
        elif idp_type == 'ping':
            assert 'connection_id' in config['idp_config'], "Missing connection_id"
        
        print("✓ Configuration valid")
        return True
        
    except Exception as e:
        print(f"✗ Configuration invalid: {e}")
        return False

if __name__ == "__main__":
    validate_config("config/config.json")
```

## Security Best Practices

### Configuration Security

1. **Never commit actual configurations**
   ```bash
   # Add to .gitignore
   config/config.json
   config/*.json
   !config/config.json.template
   ```

2. **Use environment variables for sensitive data**
   ```json
   {
     "idp_config": {
       "idp_type": "okta",
       "okta_tenant_id": "${OKTA_TENANT_ID}"
     }
   }
   ```

3. **Encrypt configuration in transit**
   - Use MDM encrypted payload delivery
   - Never send configurations over unencrypted channels

4. **Restrict file permissions**
   ```bash
   chmod 600 config/config.json
   chown root:root config/config.json
   ```

### Multi-Tenant Configuration

For organizations with multiple teams or environments:

```json
{
  "teams": {
    "engineering": {
      "postman_team_name": "acme-engineering",
      "idp_config": { ... }
    },
    "marketing": {
      "postman_team_name": "acme-marketing",
      "idp_config": { ... }
    }
  },
  "team_selection": "auto"  // or "prompt"
}
```

## Troubleshooting Configuration

### Common Configuration Issues

#### "Missing required field"
- Ensure all required fields are present
- Check for typos in field names
- Validate JSON syntax

#### "Invalid IdP type"
- Must be one of: `okta`, `azure`, `ping`, `generic`
- Case-sensitive

#### "Certificate not found"
- Check file paths are relative to daemon directory
- Ensure certificates exist at specified paths
- Verify file permissions

#### "Port already in use"
- Change `listen_port` to unused port
- Or stop conflicting service

### Configuration Testing

Test configuration without full deployment:

```bash
# Dry run mode
sudo python3 src/saml_enforcer.py --config config/config.json --dry-run

# Validate only
sudo python3 src/saml_enforcer.py --config config/config.json --validate
```

## Migration Guide

### From Previous Versions

If migrating from an older configuration format:

1. **Backup existing configuration**
   ```bash
   cp config/config.json config/config.json.backup
   ```

2. **Update structure**
   - Move IdP settings under `idp_config`
   - Move advanced settings under `advanced`
   - Update field names to current format

3. **Validate new configuration**
   ```bash
   python3 tools/validate_config.py config/config.json
   ```

4. **Test with dry run**
   ```bash
   sudo python3 src/saml_enforcer.py --config config/config.json --dry-run
   ```

5. **Deploy**
   ```bash
   sudo ./scripts/daemon_manager.sh restart
   ```