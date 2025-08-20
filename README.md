# Postman SAML Enforcer

Enterprise SAML enforcement daemon for Postman Desktop and web applications.

## Overview

This daemon intercepts Postman authentication requests and enforces SAML-only authentication by redirecting users directly to your enterprise SSO provider. It eliminates team selection and authentication method choice, ensuring users always authenticate through your configured SAML identity provider.

## How It Works

The daemon operates as an SSL-terminating proxy that:
- Modifies `/etc/hosts` to redirect `identity.getpostman.com` to localhost
- Intercepts authentication requests on specific paths (`/login`, `/enterprise/login`, `/enterprise/login/authchooser`)
- Redirects intercepted requests to your SAML identity provider
- Proxies all other requests transparently to the upstream server

## Configuration

Create `config/config.json` with your SAML settings:

```json
{
  "postman_team_name": "your-team-name",
  "saml_init_url": "https://identity.getpostman.com/sso/okta/your-tenant-id/init",
  "ssl_cert": "ssl/cert.pem",
  "ssl_key": "ssl/key.pem"
}
```

**Supported IdP Types:**
- Okta: `https://identity.getpostman.com/sso/okta/tenant-id/init`
- Azure AD: `https://identity.getpostman.com/sso/adfs/tenant-id/init`
- Generic SAML: `https://identity.getpostman.com/sso/saml/tenant-id/init`

## Usage

Start the daemon:
```bash
sudo ./scripts/daemon_manager.sh start
```

Stop the daemon:
```bash
sudo ./scripts/daemon_manager.sh stop
```

Check status:
```bash
sudo ./scripts/daemon_manager.sh status
```

## Requirements

- **Administrative privileges** - Required for port 443 binding, hosts file modification, and certificate trust
- **SSL certificate trust** - The daemon generates a self-signed certificate that must be trusted by the system
- **Network connectivity** - Access to the real `identity.getpostman.com` for proxying non-authentication requests

## SSL Certificates

The daemon automatically generates self-signed SSL certificates on first startup. The certificate configuration is stored in `ssl/cert.conf` and includes the necessary Subject Alternative Names for proper SSL termination.

## Enterprise Deployment

For enterprise deployment:
1. Configure your SAML identity provider URL in `config/config.json`
2. Run the start command with appropriate administrative privileges
3. The daemon will automatically handle certificate generation and system trust
4. Monitor logs for successful startup and request interception

## Security Notes

- The daemon only intercepts authentication paths, all other traffic is proxied transparently
- SSL connections use proper SNI headers for compatibility with CDN infrastructure
- Certificate trust is limited to SSL-only scope to minimize security impact
- The daemon binds only to localhost (127.0.0.1) to prevent interference with other applications