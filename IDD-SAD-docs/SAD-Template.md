# Solution Architecture Document (SAD)
## Postman Enterprise Control Solution

### Document Information
- **Document Version**: 1.0
- **Date**: [TO BE COMPLETED]
- **Architect**: [TO BE COMPLETED]
- **Reviewed By**: [TO BE COMPLETED]
- **Approved By**: [TO BE COMPLETED]
- **Status**: Draft

**Architecture Note**: This document reflects the current simplified SAML enforcement daemon architecture. The solution has been streamlined to use a standalone Python daemon with SSL termination rather than complex enterprise security platform integrations, reducing deployment complexity while maintaining full SAML enforcement functionality.

---

## 1. Executive Summary

[TO BE COMPLETED: High-level architectural overview and key design decisions]

---

## 2. Architecture Overview

### 2.1 Business Context
[TO BE COMPLETED: Business requirements driving the architectural decisions]

### 2.2 Architectural Principles
[TO BE COMPLETED: Key principles guiding the solution design]

### 2.3 Architecture Goals
[TO BE COMPLETED: What the architecture aims to achieve]

---

## 3. Current State Architecture

### 3.1 Application Landscape
[TO BE COMPLETED: Current application deployment patterns and management]

### 3.2 Identity and Access Management
[TO BE COMPLETED: Current IAM systems and processes]

### 3.3 Network and Security Controls
[TO BE COMPLETED: Existing network security infrastructure]

### 3.4 Current State Challenges
[TO BE COMPLETED: Limitations and issues with current state]

---

## 4. Target State Architecture

### 4.1 High-Level Architecture Diagram
[TO BE COMPLETED: Overall system architecture diagram]

### 4.2 Component Architecture

#### 4.2.1 Application Control Layer
**Windows Environment:**
- **Technology**: Microsoft AppLocker
- **Mechanism**: MSI Product Code enforcement
- **Target Product Code**: `{BB89068A-C19C-5419-A2B4-0224CDC279EF}`
- **Enforcement Method**: Publisher certificate blocking + explicit MSI allowlisting
- **Management**: Group Policy deployment via Active Directory

**macOS Environment:**
- **Technology**: Configuration Profiles
- **Mechanism**: Bundle Identifier restrictions  
- **Target Bundle IDs**: 
  - Block: `com.postmanlabs.mac`
  - Allow: `com.postmanlabs.enterprise.mac`
- **Management**: MDM deployment (Jamf/Intune)

#### 4.2.2 SAML Enforcement Layer
**Standalone Daemon:**
- **Interception Target**: `identity.getpostman.com` (via hosts file redirection)
- **Listen Port**: 443 (HTTPS SSL-terminating proxy)
- **Specific URL Paths**:
  - `/login`
  - `/enterprise/login`  
  - `/enterprise/login/authchooser`
- **SAML Enforcement**: HTTP 302 redirects to corporate Identity Provider
- **Parameter Preservation**: 
  - `auth_challenge` - Authentication challenge tokens
  - `continue` - Post-authentication redirect URLs
  - `team` - Postman team identifier
- **Transparent Proxy**: All non-authentication requests proxied to upstream

**SAML Flow Architecture:**
```
User Request → Hosts File Redirect → Daemon Interception → Parameter Extraction → 
Corporate SAML IDP → SAML Response → Postman Enterprise Authentication → Authorized Access
```

#### 4.2.3 Identity and Access Management
[TO BE COMPLETED: SAML integration, user provisioning, role management]

### 4.3 Data Flow Architecture
[TO BE COMPLETED: How data flows between components]

### 4.4 Security Architecture
[TO BE COMPLETED: Security controls and mechanisms]

---

## 5. Technology Stack

### 5.1 Core Technologies

**Windows Platform:**
- **Application Control**: Microsoft AppLocker
- **Deployment**: Group Policy Management Console (GPMC)
- **Certificate Authority**: DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
- **Package Format**: MSI (Windows Installer)

**macOS Platform:**  
- **Application Control**: Configuration Profiles (MDM)
- **Deployment**: Mobile Device Management (Jamf Pro/Microsoft Intune)
- **Certificate Authority**: Apple Developer ID Certification Authority
- **Package Format**: PKG (macOS Installer)

**SAML Enforcement:**
- **SAML Daemon**: Standalone Python daemon (SSL-terminating proxy)
- **SAML Protocol**: Security Assertion Markup Language 2.0  
- **SSL/TLS**: Self-signed certificate-based HTTPS termination
- **DNS Control**: /etc/hosts file modification for domain redirection
- **Port**: 443 (HTTPS) with localhost (127.0.0.1) binding

### 5.2 Integration Points
[TO BE COMPLETED: How components integrate with existing systems]

### 5.3 Development and Deployment Tools
[TO BE COMPLETED: Tools used for development and deployment]

---

## 6. Detailed Component Design

### 6.1 Windows AppLocker Implementation

**Policy Structure:**
```xml
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <!-- Certificate-based blocking with MSI allowlisting -->
  </RuleCollection>
</AppLockerPolicy>
```

**Key Design Decisions:**
- **Certificate-based blocking**: Blocks all executables signed by Postman, Inc. certificate
- **MSI Product Code allowlisting**: Explicitly allows only enterprise MSI installation
- **Bypass resistance**: Handles file renaming, copying, portable versions
- **Centralized management**: Group Policy deployment across all Windows endpoints

### 6.2 macOS Configuration Profile Implementation

**Payload Structure:**
```xml
<dict>
  <key>PayloadType</key>
  <string>com.apple.applicationaccess</string>
  <!-- Bundle ID-based restrictions -->
</dict>
```

**Key Design Decisions:**
- **Bundle ID enforcement**: Uses cryptographically signed application identifiers
- **MDM deployment**: Centralized configuration management
- **Certificate preservation**: Maintains code signing validation
- **Location independence**: Works regardless of application install path

### 6.3 SAML Enforcement Daemon Implementation

**Daemon Architecture:**
```python
# Core interception logic
def _handle_request(self):
    """
    Intercepts authentication requests and redirects to SAML
    Proxies all other requests transparently to upstream
    """
    clean_path = parsed_url.path.rstrip('/')
    intercept_paths = ['/login', '/enterprise/login', '/enterprise/login/authchooser']
    
    if host == "identity.getpostman.com" and clean_path in intercept_paths:
        self._handle_saml_redirect(query_params, auth_challenge)
    else:
        self._proxy_to_upstream(host, path, method)
```

**Configuration Structure:**
```json
{
  "postman_team_name": "your-team-name",
  "saml_init_url": "https://identity.getpostman.com/sso/okta/tenant-id/init",
  "ssl_cert": "ssl/cert.pem", 
  "ssl_key": "ssl/key.pem"
}
```

**Key Design Decisions:**
- **Hosts file redirection**: Redirects identity.getpostman.com to localhost (127.0.0.1)
- **SSL termination**: Self-signed certificate with proper SNI handling
- **Selective interception**: Only authentication paths are intercepted
- **Transparent proxying**: All other traffic passes through to upstream
- **Parameter preservation**: Maintains auth_challenge and continue URLs
- **Administrative privileges**: Requires sudo for port 443 and certificate trust

---

## 7. Deployment Architecture

### 7.1 Deployment Model
[TO BE COMPLETED: How the solution is deployed across environments]

### 7.2 Environment Strategy
[TO BE COMPLETED: Development, test, production environment approach]

### 7.3 Release Management
[TO BE COMPLETED: How releases are managed and deployed]

---

## 8. Operational Architecture

### 8.1 Monitoring and Observability
[TO BE COMPLETED: How the solution is monitored]

### 8.2 Logging and Auditing
[TO BE COMPLETED: Audit trail and compliance logging]

### 8.3 Backup and Recovery
[TO BE COMPLETED: Data protection and disaster recovery]

### 8.4 Performance Management
[TO BE COMPLETED: Performance monitoring and optimization]

---

## 9. Security Architecture

### 9.1 Security Controls
[TO BE COMPLETED: Security mechanisms and controls]

### 9.2 Threat Model
[TO BE COMPLETED: Security threats and mitigations]

### 9.3 Compliance Requirements
[TO BE COMPLETED: Regulatory and compliance considerations]

---

## 10. Integration Architecture

### 10.1 System Integrations
[TO BE COMPLETED: How this solution integrates with other systems]

### 10.2 API Design
[TO BE COMPLETED: API specifications and contracts]

### 10.3 Data Exchange Patterns
[TO BE COMPLETED: How data is exchanged between systems]

---

## 11. Scalability and Performance

### 11.1 Scalability Requirements
[TO BE COMPLETED: Expected load and growth patterns]

### 11.2 Performance Requirements
[TO BE COMPLETED: Performance targets and SLAs]

### 11.3 Capacity Planning
[TO BE COMPLETED: Resource requirements and capacity planning]

---

## 12. Availability and Resilience

### 12.1 Availability Requirements
[TO BE COMPLETED: Uptime and availability targets]

### 12.2 Failover and Recovery
[TO BE COMPLETED: How the system handles failures]

### 12.3 Business Continuity
[TO BE COMPLETED: Business continuity planning]

---

## 13. Migration and Transition

### 13.1 Migration Strategy
[TO BE COMPLETED: How to move from current to target state]

### 13.2 Transition Planning
[TO BE COMPLETED: Detailed transition steps and sequencing]

### 13.3 Rollback Strategy
[TO BE COMPLETED: How to rollback if needed]

---

## 14. Governance and Compliance

### 14.1 Architecture Governance
[TO BE COMPLETED: How architecture decisions are governed]

### 14.2 Compliance Framework
[TO BE COMPLETED: Compliance requirements and validation]

### 14.3 Risk Management
[TO BE COMPLETED: Risk assessment and mitigation strategies]

---

## 15. Future State Considerations

### 15.1 Technology Roadmap
[TO BE COMPLETED: Future technology evolution plans]

### 15.2 Enhancement Opportunities
[TO BE COMPLETED: Potential future improvements]

### 15.3 Emerging Technologies
[TO BE COMPLETED: Impact of emerging technologies]

---

## Appendices

### Appendix A: Technical Specifications

#### A.1 Windows AppLocker Rule Specifications
**Complete XML Policy:**
```xml
<!-- Complete AppLocker Rules for Group Policy Deployment -->
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">

    <!-- DENY: Block ALL Postman executables by certificate -->
    <PublisherRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" 
                   Name="Block All Postman Executables" 
                   Description="Block all Postman versions by publisher certificate" 
                   UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <PublisherCondition PublisherName="CN=Postman, Inc., O=Postman, Inc., L=San Francisco, S=California, C=US" 
                           ProductName="*" 
                           BinaryName="*"/>
      </Conditions>
    </PublisherRule>

    <!-- ALLOW: Only Enterprise via MSI Product Code -->
    <ProductCodeRule Id="b9c5a434-9c70-421c-96d8-e6be0c5aff7c" 
                     Name="Allow Enterprise Postman Only" 
                     Description="Explicitly allow only MSI-installed Enterprise Postman" 
                     UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <ProductCodeCondition ProductCode="{BB89068A-C19C-5419-A2B4-0224CDC279EF}"/>
      </Conditions>
    </ProductCodeRule>

  </RuleCollection>
</AppLockerPolicy>
```

#### A.2 macOS Configuration Profile Specifications
**Complete Configuration Profile:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.applicationaccess</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.company.postman.restrictions</string>
            <key>PayloadUUID</key>
            <string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string>
            <key>PayloadDisplayName</key>
            <string>Block Consumer Postman</string>

            <key>familyControlsEnabled</key>
            <true/>
            <key>blacklistedAppBundleIDs</key>
            <array>
                <string>com.postmanlabs.mac</string>
            </array>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>Postman Enterprise Control Policy</string>
    <key>PayloadIdentifier</key>
    <string>com.company.postman.control</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>B2C3D4E5-F6G7-8901-BCDE-F23456789012</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
```

#### A.3 SAML Enforcement Daemon Configuration
**Configuration JSON Template:**
```json
{
  "postman_team_name": "your-team-name",
  "saml_init_url": "https://identity.getpostman.com/sso/okta/tenant-id/init",
  "ssl_cert": "ssl/cert.pem",
  "ssl_key": "ssl/key.pem"
}
```

**Supported SAML Identity Providers:**
- **Okta**: `https://identity.getpostman.com/sso/okta/tenant-id/init`
- **Azure AD (ADFS)**: `https://identity.getpostman.com/sso/adfs/tenant-id/init`
- **Generic SAML**: `https://identity.getpostman.com/sso/saml/tenant-id/init`

**Daemon Management Commands:**
```bash
# Start daemon (requires sudo for port 443 and certificate trust)
sudo ./scripts/daemon_manager.sh start

# Check daemon status
sudo ./scripts/daemon_manager.sh status

# Stop daemon and clean up hosts file
sudo ./scripts/daemon_manager.sh stop

# Restart daemon
sudo ./scripts/daemon_manager.sh restart
```

### Appendix B: Network Diagrams
[TO BE COMPLETED: Detailed network and data flow diagrams]

### Appendix C: Security Controls Matrix
[TO BE COMPLETED: Mapping of security controls to requirements]

### Appendix D: Glossary
[TO BE COMPLETED: Technical terms and definitions]

### Appendix E: References
[TO BE COMPLETED: Related documents, standards, and specifications]