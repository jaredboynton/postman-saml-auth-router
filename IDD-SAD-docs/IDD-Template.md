# Implementation Design Document (IDD)
## Postman Enterprise Control Solution

### Document Information
- **Document Version**: 1.0
- **Date**: [TO BE COMPLETED]
- **Prepared By**: [TO BE COMPLETED]
- **Approved By**: [TO BE COMPLETED]
- **Status**: Draft

**Architecture Note**: This document reflects the current simplified SAML enforcement daemon implementation. The solution uses a standalone SSL-terminating proxy daemon rather than complex third-party integrations, providing enterprise SAML enforcement with minimal deployment complexity.

---

## 1. Executive Summary

[TO BE COMPLETED: Brief overview of the project, business drivers, and expected outcomes]

---

## 2. Business Justification

### 2.1 Business Drivers
[TO BE COMPLETED: Why this project is needed - compliance, security, governance requirements]

### 2.2 Problem Statement  
[TO BE COMPLETED: Current state challenges with consumer Postman usage]

### 2.3 Proposed Solution Overview
[TO BE COMPLETED: High-level description of enterprise control approach]

### 2.4 Cost/Benefit Analysis
[TO BE COMPLETED: Implementation costs vs security/compliance benefits]

---

## 3. Technical Solution Architecture

### 3.1 Current State Analysis

#### Windows Consumer Postman
- **Version**: 11.59.1
- **Installer Type**: Squirrel.Windows executable (.exe)
- **Company**: Postman, Inc.
- **Main Executable**: Postman.exe
- **Installation Framework**: Squirrel auto-updater
- **Default Install Path**: %LOCALAPPDATA%\Postman\ (user-level install)
- **Package Format**: .nupkg (NuGet package)
- **Update Mechanism**: Update.exe + squirrel.exe (automatic updates)
- **Certificate Subject**: CN=Postman, Inc., O=Postman, Inc., L=San Francisco, S=California, C=US
- **Certificate Issuer**: DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
- **Product Code**: None (Squirrel-based)

#### Windows Enterprise Postman
- **Version**: 11.58.0
- **Installer Type**: MSI package
- **Company**: Postman
- **Main Executable**: Postman Enterprise.exe
- **Installation Framework**: Windows Installer
- **Default Install Path**: C:\Program Files\Postman\Postman Enterprise\
- **Package Format**: .msi (Windows Installer package)
- **Update Mechanism**: Manual/controlled updates via MSI
- **Certificate Subject**: CN=Postman, Inc., O=Postman, Inc., L=San Francisco, S=California, C=US
- **Certificate Issuer**: DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
- **Product Code**: {BB89068A-C19C-5419-A2B4-0224CDC279EF}
- **Component GUIDs**: Multiple component identifiers

#### macOS Consumer Postman
- **Version**: 11.59.1
- **Installer Type**: ZIP archive
- **Company**: Postdot Technologies, Inc
- **Main Executable**: Postman (inside app bundle)
- **Installation Framework**: Manual drag-and-drop
- **Default Install Path**: /Applications/Postman.app
- **Package Format**: .zip containing .app bundle
- **Update Mechanism**: Automatic in-app updates
- **Bundle Identifier**: com.postmanlabs.mac
- **Team Identifier**: H7H8Q7M5CK
- **Certificate Subject**: CN=Developer ID Application: Postdot Technologies, Inc (H7H8Q7M5CK)
- **Certificate Issuer**: CN=Developer ID Certification Authority, OU=Apple Certification Authority

#### macOS Enterprise Postman
- **Version**: 11.58.0-enterprise01
- **Installer Type**: PKG installer
- **Company**: Postdot Technologies, Inc
- **Main Executable**: Postman Enterprise (inside app bundle)
- **Installation Framework**: macOS Installer (PKG)
- **Default Install Path**: /Applications/Postman Enterprise.app
- **Package Format**: .pkg (macOS Installer package)
- **Update Mechanism**: Manual/controlled updates via PKG
- **Bundle Identifier**: com.postmanlabs.enterprise.mac
- **Team Identifier**: H7H8Q7M5CK
- **Certificate Subject**: CN=Developer ID Application: Postdot Technologies, Inc (H7H8Q7M5CK)
- **Certificate Issuer**: CN=Developer ID Certification Authority, OU=Apple Certification Authority
- **Package Identifier**: com.postmanlabs.enterprise.mac (PKG level)

### 3.2 Target State Architecture

#### Layer 1: Application Control
- **Windows**: AppLocker with MSI Product Code enforcement
- **macOS**: Configuration Profiles with Bundle ID restrictions

#### Layer 2: SAML Enforcement Daemon
- **SSL-Terminating Proxy**: Intercepts identity.getpostman.com on port 443
- **Hosts File Modification**: Redirects domain to localhost (127.0.0.1)
- **SAML Enforcement**: Redirects authentication requests to corporate SAML identity provider
- **Parameter Preservation**: Maintains auth_challenge and continue URL parameters
- **Configuration Parameters**:
  - `postman_team_name`: Corporate team identifier
  - `saml_init_url`: Corporate SAML initialization endpoint (Okta/Azure AD/Generic)
  - `ssl_cert`: SSL certificate path for HTTPS termination
  - `ssl_key`: SSL private key path

#### Layer 3: Identity & Access Control
- **SAML Integration**: Corporate Identity Provider integration
- **Team Management**: Centralized Postman Enterprise team provisioning
- **Audit Logging**: Authentication and usage monitoring

---

## 4. Implementation Plan

### 4.1 Phase 1: Pilot Implementation
[TO BE COMPLETED: Pilot group selection, testing procedures, success criteria]

### 4.2 Phase 2: Department Rollout
[TO BE COMPLETED: Departmental deployment strategy, support procedures]

### 4.3 Phase 3: Enterprise Deployment
[TO BE COMPLETED: Full enterprise rollout, monitoring, optimization]

### 4.4 Implementation Milestones
[TO BE COMPLETED: Key deliverables and success criteria for each phase]

---

## 5. Technical Implementation Details

### 5.1 Windows Deployment
Deploy via Group Policy
Path: Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker

**AppLocker Rules:**
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

**Verification:**
```powershell
Get-AppLockerPolicy -Effective | Format-List
```

### 5.2 macOS Deployment
Deploy via MDM or manual installation:
```bash
sudo profiles install -path PostmanControl.mobileconfig
```

**Configuration Profile:**
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

**Verification:**
```bash
profiles list | grep -i postman
```

### 5.3 SAML Enforcement Daemon Deployment

**Daemon Configuration:**
- **Target Domain**: identity.getpostman.com (via /etc/hosts modification)
- **Listen Port**: 443 (HTTPS)
- **Interception Paths**: /login, /enterprise/login, /enterprise/login/authchooser
- **Parameter Preservation**: auth_challenge, continue URLs, team identifiers
- **Redirect Mechanism**: HTTP 302 to corporate SAML identity provider
- **Proxy Function**: All non-authentication requests proxied transparently to upstream

**Daemon Startup Commands:**
```bash
# Start daemon
sudo ./scripts/daemon_manager.sh start

# Check status
sudo ./scripts/daemon_manager.sh status

# Stop daemon
sudo ./scripts/daemon_manager.sh stop
```

**Configuration File (config/config.json):**
```json
{
  "postman_team_name": "your-team-name",
  "saml_init_url": "https://identity.getpostman.com/sso/okta/tenant-id/init",
  "ssl_cert": "ssl/cert.pem",
  "ssl_key": "ssl/key.pem"
}
```

**Supported Identity Providers:**
- **Okta**: `https://identity.getpostman.com/sso/okta/tenant-id/init`
- **Azure AD**: `https://identity.getpostman.com/sso/adfs/tenant-id/init`
- **Generic SAML**: `https://identity.getpostman.com/sso/saml/tenant-id/init`

---

## 6. Risk Assessment and Mitigation

### 6.1 Technical Risks
[TO BE COMPLETED: Technical implementation risks and mitigation strategies]

### 6.2 Business Risks  
[TO BE COMPLETED: User productivity, workflow disruption risks]

### 6.3 Security Risks
[TO BE COMPLETED: Security considerations and controls]

### 6.4 Rollback Procedures
[TO BE COMPLETED: How to reverse implementation if needed]

---

## 7. Dependencies and Prerequisites

### 7.1 Infrastructure Dependencies
[TO BE COMPLETED: Required systems, networks, services]

### 7.2 Organizational Dependencies  
[TO BE COMPLETED: Team resources, training, communication]

### 7.3 Technical Prerequisites
[TO BE COMPLETED: Software versions, system requirements]

---

## 8. Success Criteria and Metrics

### 8.1 Technical Success Criteria
[TO BE COMPLETED: Measurable technical outcomes]

### 8.2 Business Success Criteria
[TO BE COMPLETED: Business value metrics]

### 8.3 Compliance Metrics
[TO BE COMPLETED: Security and compliance measurements]

---

## 9. Support and Operations

### 9.1 Support Procedures
[TO BE COMPLETED: How users get help, escalation procedures]

### 9.2 Monitoring and Alerting
[TO BE COMPLETED: Operational monitoring requirements]

### 9.3 Maintenance Procedures  
[TO BE COMPLETED: Ongoing maintenance tasks and procedures]

---

## 10. Testing Strategy

### 10.1 Unit Testing
[TO BE COMPLETED: Component-level testing approach]

### 10.2 Integration Testing
[TO BE COMPLETED: System integration testing]

### 10.3 User Acceptance Testing
[TO BE COMPLETED: End-user testing procedures]

---

## 11. Communication Plan

### 11.1 Stakeholder Communication
[TO BE COMPLETED: Who needs to be informed and when]

### 11.2 User Communication
[TO BE COMPLETED: End-user notification and training plan]

### 11.3 Change Management
[TO BE COMPLETED: Managing organizational change]

---

## Appendices

### Appendix A: Glossary
[TO BE COMPLETED: Technical terms and definitions]

### Appendix B: References  
[TO BE COMPLETED: Related documents and standards]

### Appendix C: Contact Information
[TO BE COMPLETED: Project team and stakeholder contacts]