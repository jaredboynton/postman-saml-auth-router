# Solution Architecture Document (SAD)
## Postman Enterprise Control Solution

### Document Information
- **Document Version**: 1.0
- **Date**: 2024-08-20
- **Architect**: [TO BE COMPLETED - Customer Solution Architect]
- **Reviewed By**: [TO BE COMPLETED - Customer Architecture Review Board]
- **Approved By**: [TO BE COMPLETED - Customer Leadership]
- **Status**: Template for Customer Implementation

**Architecture Note**: This document reflects the complete Postman Enterprise deployment architecture including enterprise application deployment, identity provider integration, SCIM provisioning, Domain Capture, and security enforcement layers.


---

## 1. Executive Summary

The Postman Enterprise Control Solution architecture implements comprehensive organizational governance over API development platforms through a multi-layered approach combining application management, identity integration, domain control, and security enforcement.

**Key Architectural Decisions:**
1. **Enterprise Application Deployment**: Centrally managed MSI/PKG packages replacing consumer installations
2. **Identity-First Architecture**: Corporate SAML SSO with automated SCIM provisioning as the foundation
3. **Domain-Based Control**: Postman Domain Capture providing organizational ownership and access control
4. **Layered Security**: Optional [SAML enforcement daemon](https://github.com/jaredboynton/postman-saml-enforcer) providing additional device trust validation
5. **Transparent Operation**: Minimal user experience impact while maintaining complete administrative control

**Architecture Benefits:**
- Complete data governance preventing unauthorized API access
- Seamless user experience preserving developer productivity
- Scalable deployment leveraging existing enterprise infrastructure
- Comprehensive audit trail and compliance capabilities

---

## 2. Architecture Overview

### 2.1 Business Context
[TO BE COMPLETED: Business requirements driving the architectural decisions]

### 2.2 Architectural Principles
**Customer-Specific Template**: Define your organization's architectural principles such as:
- Security-first design approach
- Minimal user experience disruption
- Leverage existing enterprise infrastructure
- Scalable and maintainable solutions
- Compliance with corporate standards

### 2.3 Architecture Goals
**Technical Goals (Achieved by Reference Architecture):**
- **Complete API Governance**: 100% visibility and control over API development activities
- **Data Loss Prevention**: Eliminate unauthorized access to corporate API credentials and schemas
- **Identity Integration**: Seamless corporate SSO with automated user provisioning
- **Device Trust Validation**: Ensure only managed devices access corporate API development resources
- **Transparent Operation**: Maintain developer productivity while enforcing security controls

**Business Goals (Customer-Specific):**
[TO BE COMPLETED: Customer-specific business objectives and success criteria]

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

#### 4.2.2 Identity Provider Integration Layer
**SAML SSO Integration:**
- **Protocol**: SAML 2.0 with corporate identity providers (Okta, Azure AD, ADFS)
- **Authentication Flow**: Standard SAML assertion exchange with Postman Enterprise
- **Attribute Mapping**: Corporate directory attributes mapped to Postman user properties
- **Session Management**: SSO session lifecycle managed by corporate identity provider

**SCIM User Provisioning:**
- **Protocol**: SCIM 2.0 for automated user lifecycle management
- **Provisioning**: Real-time user creation, updates, and deprovisioning
- **Team Assignment**: Automated team membership based on directory group membership
- **Attribute Synchronization**: User profile data sync from corporate directory

#### 4.2.3 Domain Control Layer
**Domain Capture Implementation:**
- **Domain Verification**: DNS TXT record or HTML file verification proving domain ownership
- **Organizational Control**: Administrative oversight of all teams within verified domain
- **Access Restrictions**: Prevent consumer Postman access for users within captured domains
- **Team Management**: Centralized team creation and membership management

#### 4.2.4 Security Enforcement Layer (Optional)
**SAML Enforcement Daemon** ([Reference Implementation](https://github.com/jaredboynton/postman-saml-enforcer)):
- **Device Trust Validation**: Ensures only managed devices can access corporate instance
- **Bidirectional Control**: Managed devices can only access corporate instance (not personal)
- **Technical Implementation**:
  - SSL interception of `identity.getpostman.com` via hosts file redirection
  - HTTPS proxy on port 443 with automatic certificate generation and trust
  - Parameter-preserving redirects to corporate SAML endpoints
  - Transparent proxy for all non-authentication requests

**Complete Security Flow:**
```
Managed Device + IDP Trust → SAML Daemon Interception → Corporate SAML Authentication → 
Postman Enterprise Access (Corporate Instance Only)
```

#### 4.2.5 Application Management Layer
**Enterprise Application Deployment:**
- **Windows**: MSI packages deployed via Group Policy or SCCM
- **macOS**: PKG installers deployed via MDM (Jamf Pro, Microsoft Intune)
- **Configuration Management**: Centralized application settings and policy enforcement
- **Update Management**: Controlled application updates through existing deployment infrastructure

**Application Control (Optional):**
- **Windows**: AppLocker policies preventing consumer Postman execution
- **macOS**: Configuration Profiles blocking consumer application bundles
- **Enforcement**: Certificate-based blocking with explicit enterprise allowlisting

### 4.3 Data Flow Architecture

**Authentication Flow:**
```
User → Postman Enterprise → SAML SSO Request → Corporate IDP → 
SAML Assertion → Postman Authentication → Workspace Access
```

**User Provisioning Flow:**
```
Corporate Directory Changes → SCIM API → Postman Enterprise → 
User/Team Provisioning → Workspace Access Control
```

**Security Enforcement Flow (Optional):**
```
Managed Device → SAML Daemon → Authentication Interception → 
Corporate IDP Redirect → Device Trust Validation → Authorized Access
```

**Administrative Control Flow:**
```
Domain Verification → Administrative Control → Team Management → 
Workspace Governance → API Collection Control → Audit Logging
```

### 4.4 Security Architecture

**Identity Security:**
- **SAML Assertions**: Cryptographically signed authentication tokens
- **Session Management**: Corporate identity provider controls session lifecycle
- **Multi-Factor Authentication**: MFA enforcement through corporate IDP
- **Device Trust**: Optional IDP device trust policies for additional security

**Network Security:**
- **HTTPS Only**: All communications encrypted in transit
- **Certificate Validation**: Proper SSL/TLS certificate chain validation
- **DNS Security**: Secure domain resolution with fallback mechanisms
- **Firewall Integration**: Outbound access controls and monitoring

**Application Security:**
- **Code Signing**: Enterprise applications validated through certificate authority
- **Privilege Separation**: Services run with minimal required system privileges
- **Configuration Security**: Sensitive configuration data properly protected
- **Update Security**: Controlled application updates through managed deployment

**Data Security:**
- **API Credential Protection**: Prevention of credential extraction to unmanaged devices
- **Workspace Isolation**: Team and workspace access controls prevent data leakage
- **Audit Logging**: Complete activity logging for compliance and incident response
- **Data Loss Prevention**: Organizational controls prevent unauthorized data access

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

**Identity Integration:**
- **SAML Protocol**: Security Assertion Markup Language 2.0 for SSO
- **SCIM Protocol**: System for Cross-domain Identity Management 2.0 for provisioning
- **Domain Verification**: DNS TXT record or HTML file verification
- **Corporate Directory**: Integration with Active Directory, LDAP, or cloud directories

**Security Enforcement (Optional Layer):**
- **SAML Daemon**: Python-based SSL-terminating proxy for device trust validation
- **SSL/TLS**: Automatic certificate generation and system trust installation
- **DNS Control**: /etc/hosts file modification for domain redirection
- **Service Management**: Windows Service and macOS LaunchDaemon deployment

### 5.2 Integration Points

**Identity Provider Integration:**
- **SAML SSO**: Standard SAML 2.0 integration with corporate identity providers
- **SCIM Provisioning**: RESTful API integration for automated user/team management
- **Attribute Mapping**: Corporate directory attributes mapped to Postman user properties
- **Group Synchronization**: Directory group membership controls Postman team assignment

**Endpoint Management Integration:**
- **Windows**: Group Policy Software Installation and SCCM application deployment
- **macOS**: MDM application deployment via Jamf Pro, Microsoft Intune, or similar
- **Configuration Management**: Centralized policy deployment and device compliance validation
- **Service Monitoring**: Integration with existing endpoint monitoring solutions

**Network Infrastructure Integration:**
- **DNS**: Corporate DNS servers for domain resolution and verification
- **Firewalls**: Outbound HTTPS access to Postman domains and identity provider endpoints
- **Certificate Authority**: Integration with corporate PKI for certificate validation
- **Audit Systems**: SIEM integration for authentication and access logging

### 5.3 Development and Deployment Tools

**Reference Implementation:**
- **Repository**: [postman-saml-enforcer](https://github.com/jaredboynton/postman-saml-enforcer)
- **Language**: Python 3.7+ with standard library modules
- **Service Management**: Cross-platform service installation and management scripts
- **Configuration**: JSON-based configuration with validation and error handling

**Deployment Automation:**
- **Windows**: PowerShell scripts for automated service installation and configuration
- **macOS**: Bash scripts for LaunchDaemon installation and service management
- **Session Management**: Python utility for clearing existing consumer Postman sessions
- **Testing**: Automated test suites for component and integration validation

**Enterprise Integration:**
- **Group Policy**: Windows administrative templates and policy deployment
- **MDM Profiles**: macOS configuration profiles for application and security control
- **Monitoring**: Health check endpoints and service status reporting
- **Maintenance**: Automated certificate renewal and service health monitoring

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
  "postman_team_name": "your-corporate-team-name",
  "saml_init_url": "https://identity.getpostman.com/sso/saml/init",
  "dns_servers": ["8.8.8.8", "1.1.1.1"],
  "ssl_cert": "ssl/cert.pem",
  "ssl_key": "ssl/key.pem",
  "listen_port": 443
}
```

**Supported SAML Identity Providers:**
- **Okta**: Full SAML 2.0 and SCIM 2.0 integration
- **Azure AD**: SAML SSO with Azure AD SCIM provisioning
- **ADFS**: On-premises Active Directory Federation Services
- **Generic SAML**: Any SAML 2.0 compliant identity provider

**Service Management Commands:**

*Windows (PowerShell as Administrator):*
```powershell
# Install and start Windows service
.\service\windows\install-service.ps1 install
.\service\windows\install-service.ps1 start

# Check service status
.\service\windows\install-service.ps1 status

# Clear sessions before deployment
.\service\windows\install-service.ps1 srefresh
```

*macOS (Terminal with sudo):*
```bash
# Install and start system daemon
sudo ./service/macos/install-service.sh install
sudo ./service/macos/install-service.sh start

# Check daemon status
sudo ./service/macos/install-service.sh status

# Clear sessions before deployment
sudo ./service/macos/install-service.sh srefresh
```

### Appendix B: Network Diagrams
[TO BE COMPLETED: Detailed network and data flow diagrams]

### Appendix C: Security Controls Matrix
[TO BE COMPLETED: Mapping of security controls to requirements]

### Appendix D: Glossary
[TO BE COMPLETED: Technical terms and definitions]

### Appendix E: References
[TO BE COMPLETED: Related documents, standards, and specifications]