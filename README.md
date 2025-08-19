# Simplified Postman SAML Enforcer - Implementation Guide

## What Changed?

Minor but significant changes were made to allow state parameters to be passed directly to the SAML `/init/` URL, avoiding the need for complex state handling and IdP-specific configuration. We can now use a streamlined approach.

## Core Architecture Simplifications

Previously, we required complex state management and IdP-specific URL construction logic. We can now utilize a simple copy-paste with simple parameter appending. Instead of maintaining separate configuration fields for tenant IDs, app IDs, and other IdP-specific parameters, the system now accepts a complete `saml_init_url` that gets used directly with preserved query parameters.

This architectural change reduces complexity significantly while maintaining full compatibility with existing SAML flows, and parameter preservation logic ensures that authentication challenges, team information, and continuation URLs are correctly forwarded to the IdP without requiring deep understanding of each provider's specific requirements.

## Configuration Format

The simplified configuration uses a single `saml_init_url` field instead of complex IdP-specific structures:

```json
{
  "postman_team_name": "your-team",
  "saml_init_url": "https://identity.getpostman.com/sso/okta/db1b1a3764f24213906d682e26fd366f/init",
  "ssl_cert": "ssl/cert.pem",
  "ssl_key": "ssl/key.pem",
  "listen_port": 443
}
```

This approach works identically across all IdP types including Okta, Azure AD, and generic SAML providers. The URL contains all necessary routing information, while the daemon handles parameter preservation and forwarding automatically.

## Basic Usage

The daemon operates as an SSL-terminating proxy that intercepts HTTPS requests to `identity.getpostman.com` on specific authentication paths. When a request matches the target paths (`/login`, `/enterprise/login`, `/enterprise/login/authchooser`), the daemon extracts query parameters and redirects the client to the configured SAML URL with those parameters preserved.

Starting the daemon requires administrative privileges for port 443 binding and certificate trust. The system modifies `/etc/hosts` to redirect the target domain to localhost, then listens for incoming HTTPS connections. All non-authentication requests are proxied transparently to the upstream server.

Certificate trust must be established before operation, as the daemon presents itself as `identity.getpostman.com` to terminate SSL connections. The certificate generation process creates a self-signed certificate with the appropriate subject alternative names, which must then be trusted by the operating system's certificate store.

## Operational Requirements

The daemon requires several system-level permissions and configurations. Administrative access is necessary for binding to port 443, modifying the hosts file, and installing trusted certificates. The SSL certificate must be trusted for the `identity.getpostman.com` domain to prevent browser warnings during SSL termination.

Network connectivity to the real `identity.getpostman.com` is required for proxying non-authentication requests. The daemon performs DNS resolution to determine the upstream IP address, then establishes SSL connections with proper SNI headers to maintain compatibility with CDN and load balancer infrastructure.

## Management Operations

Simplified daemon management -- just start, stop. The simplified architecture eliminates most troubleshooting complexity since the configuration is straightforward and the URL construction logic is minimal. Log files provide insight into request routing decisions and any errors encountered during SSL termination or upstream proxying.

Certificate renewal follows standard SSL certificate practices, though the self-signed approach means generating new certificates periodically and updating the trust store. The daemon automatically loads certificate changes when restarted, requiring no configuration updates for certificate rotation.

## Deployment Strategy

A minimal deployment approach would involve certificate generation and trust establishment, hosts file modification, daemon installation, and service configuration. 

The deployment process would utilize Enterprise CA certificates with appropriate subject alternative names for the target domain. System configuration includes adding the localhost redirect to the hosts file and establishing certificate trust through the operating system's certificate management interface. The daemon binary would be installed with appropriate permissions and configured to start automatically.

Service management would use standard system service frameworks like systemd on Linux or launchd on macOS. The minimal configuration requirements make automation straightforward, requiring only the SAML URL and basic daemon settings to be customized per organization.

## Alternative Approaches

Two new proof-of-concept alternatives demonstrate how enterprise infrastructure could handle SAML enforcement without custom daemon deployment. 

1. **[Zscaler Client Connector POC](poc/zscaler-poc/)** - Shows how device-level proxy agents could implement the same functionality using PAC files and local proxy components.
2. **[DNS Interceptor POC](poc/dns-interceptor/)** - Demonstrates how local DNS servers could replace hosts file modification while maintaining the same SSL termination and redirect logic.

Both alternatives maintain identical parameter handling and SAML redirect behavior while eliminating a certain amount of deployment complexity. The enterprise proxy approach removes the need for hosts file modification and port 443 binding, while the DNS approach provides a more standard network interception method. That said, all approaches require certificate trust establishment for SSL termination capabilities.