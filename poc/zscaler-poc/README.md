# Zscaler Client Connector POC - SAML Enforcement Demo

## Overview
This proof-of-concept demonstrates how Zscaler Client Connector could implement device-level Postman SAML enforcement using PAC files and local proxy agents, eliminating the need for hosts file modification or custom daemon deployment. The POC shows how Zscaler's existing device-level proxy infrastructure could handle Postman SAML enforcement through cloud-managed policies without requiring custom daemon installation.

## Architecture
```
Client (Postman) 
    |
    | System Proxy Check
    v
Zscaler PAC File ──> if (identity.getpostman.com) → proxy 127.0.0.1:8444
    |                else → DIRECT
    v
Zscaler SAML Agent (port 8444) ──> Intercepts /login paths  
    |
    v
Redirect to SAML IdP
```

## Components

The Zscaler PAC file serves as a JavaScript function that defines proxy rules for the client system. This file routes traffic for `identity.getpostman.com` to the local Zscaler agent while maintaining direct connections for all other domains. In a production environment, this PAC file would be deployed via Zscaler cloud policy management rather than manual configuration.

The Zscaler SAML agent operates as an HTTP proxy on port 8444, providing SSL termination for intercepted traffic while implementing the same path inspection and redirect logic as the original daemon. This agent maintains the same certificate trust requirements as the current solution but operates on a non-privileged port, making deployment more straightforward.

System proxy configuration varies by platform but follows standard enterprise patterns. On Windows systems, this involves Internet Options or Registry configuration, while Mac systems use System Preferences Network Proxies settings. In both cases, the configuration points to either a local PAC file using a file:// URL or a remote PAC file hosted by Zscaler's infrastructure.

## Benefits

This approach eliminates hosts file modification entirely, which removes one of the more intrusive aspects of the current implementation. The solution uses standard enterprise proxy configuration methods that IT administrators are already familiar with and comfortable managing. Since the agent runs on a non-privileged port, it doesn't require the same level of system access as binding to port 443. The system becomes easier to disable through standard proxy settings rather than requiring file system modifications.

## Requirements

The certificate trust requirements remain the same as the current daemon implementation, since SSL termination is still necessary to inspect the request paths. System proxy configuration permissions are needed, though these are typically less restrictive than hosts file modification. PAC file deployment can use either local file:// URLs for testing or http:// URLs for production deployment through enterprise infrastructure.

## Testing Approach

Testing this POC involves creating and deploying the PAC file to the target system, then configuring the system proxy to use this PAC file for routing decisions. The proxy-mode daemon starts on port 8444 to handle intercepted traffic. Postman Desktop testing verifies that the application correctly follows system proxy configuration. Authentication flow validation ensures that parameter preservation and SAML redirects function correctly. Cross-platform compatibility testing would verify operation on both Windows and Mac systems, though this POC focuses on Mac implementation.

## Directory Structure

The `src/` directory contains the proxy-mode daemon code and PAC file generator that would be equivalent to Zscaler's local agent components. Configuration templates in the `config/` directory provide the foundation for both daemon configuration and PAC file generation. The `scripts/` directory includes PAC deployment and system proxy management scripts that demonstrate how Zscaler could automate these processes. SSL certificates in the `ssl/` directory maintain the same trust requirements as the current implementation.

## PAC File Implementation

The PAC file uses standard JavaScript syntax to define routing rules:

```javascript
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "identity.getpostman.com")) {
        return "PROXY 127.0.0.1:8444";
    }
    return "DIRECT";
}
```

This simple logic demonstrates how Zscaler could implement domain-specific routing through their existing PAC file infrastructure, requiring minimal changes to their current proxy management capabilities.