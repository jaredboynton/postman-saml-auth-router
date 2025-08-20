# Implementation Design Document (IDD)
## Postman Enterprise Control Solution

### Document Information
- **Document Version**: 1.0
- **Date**: 2024-08-20
- **Prepared By**: Security Architecture Team
- **Approved By**: Enterprise Security Leadership
- **Status**: Current Implementation

**Architecture Note**: This document reflects the complete Postman Enterprise deployment architecture including enterprise application deployment, identity provider integration, SCIM provisioning, Domain Capture implementation, and additional security enforcement layers.

---

## 1. Executive Summary

The Postman Enterprise Control Solution implements comprehensive organizational governance over API development platforms through enterprise application deployment, identity integration, domain management, and security enforcement. This multi-layered approach ensures all API development activities occur within corporate security boundaries with complete administrative control and audit visibility.

**Key Components:**
1. **Enterprise Application Deployment**: Managed MSI (Windows) and PKG (macOS) installation replacing consumer versions
2. **Identity Provider Integration**: Corporate SAML/SSO with automated SCIM user provisioning
3. **Domain Capture & Verification**: Organizational control over postman.com access and team management
4. **Centralized Administration**: Complete workspace, team, and API collection governance
5. **Security Enforcement**: Complete data lockdown through Domain Capture + IDP device trust + [SAML enforcement daemon](https://github.com/jaredboynton/postman-saml-enforcer) ensuring only managed devices access corporate instance and managed devices cannot access other instances
6. **Migration & Support**: Comprehensive transition from consumer to enterprise deployment

**Business Outcome:** Complete enterprise governance of API development ecosystem preventing unauthorized data access while maintaining developer productivity and enabling centralized security oversight.

---

## 2. Business Justification

### 2.1 Business Drivers
- **Data Loss Prevention**: Prevent API credentials and sensitive data extraction to personal/unmanaged devices
- **Compliance Requirements**: Ensure all API development occurs within corporate security perimeter
- **Identity Governance**: Centralize access control through corporate SAML identity providers
- **Device Trust Enforcement**: Mandatory daemon ensures only managed devices can access Postman Enterprise
- **Audit and Monitoring**: Complete visibility into API development platform usage

### 2.2 Problem Statement  
- Users can install consumer Postman on personal devices and extract corporate API credentials
- No mechanism to enforce corporate identity provider authentication for API platform access
- Lack of device trust validation allows data extraction to unmanaged endpoints
- Limited visibility and control over API development activities outside corporate environment

### 2.3 Proposed Solution Overview
Implement comprehensive enterprise control through multiple layers:

**Core Enterprise Platform:**
1. **Enterprise Application Deployment**: Replace consumer Postman with managed enterprise versions
2. **Identity Integration**: Corporate SAML/SSO with automated SCIM provisioning  
3. **Domain Capture**: Organizational control preventing consumer access to corporate teams
4. **Administrative Governance**: Complete visibility and control over API development activities

**Enforcement Strategy** (Required for complete control):
Without enforcement mechanisms, users can bypass enterprise controls by accessing consumer Postman from personal devices or using consumer apps on managed devices. The solution implements SAML enforcement daemon as the preferred approach because:

- **Superior User Experience**: Transparent authentication redirection vs. blocking/error messages
- **Location Independent**: Works from any network (home, VPN, corporate) vs. network-dependent solutions
- **Preserves Functionality**: Apps continue to work normally vs. disruptive blocking approaches  
- **Comprehensive Coverage**: Prevents bypass regardless of installation method or device type

**Result**: Complete organizational control over API development with optimal user experience and productivity preservation.

### 2.4 Cost/Benefit Analysis

**Implementation Costs:**
- **Enterprise Licensing**: Postman Enterprise subscription for managed users
- **Integration Effort**: SAML/SCIM configuration with existing identity provider (typically 1-2 weeks)
- **Deployment**: Leverages existing MDM/Group Policy infrastructure for application and enforcement deployment
- **Training**: User training on enterprise workspace management and migration assistance

**Operational Costs:**
- **Low Ongoing Overhead**: Automated user provisioning via SCIM; centralized application management
- **Reduced Support**: Eliminated shadow IT and unauthorized API tool usage
- **Enforcement Efficiency**: SAML daemon approach minimizes user friction and support tickets vs. blocking alternatives

**Security & Compliance Benefits:**
- **Complete Data Protection**: Prevention of API credential and sensitive data extraction to unmanaged environments
- **Full Audit Trail**: Comprehensive visibility into all API development activities and access patterns
- **Regulatory Compliance**: Meets SOC 2, GDPR, and industry-specific data governance requirements
- **Risk Mitigation**: Eliminates unauthorized API access and prevents intellectual property exposure

**ROI Calculation:**
- **Immediate**: Prevention of potential data breach incidents and regulatory penalties
- **Productivity**: Maintained developer efficiency through superior UX enforcement approach
- **Governance**: Administrative control enabling secure API development at organizational scale

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

#### Layer 1: Enterprise Application Deployment
- **Windows**: MSI package deployment via Group Policy/SCCM
  - Product Code: `{BB89068A-C19C-5419-A2B4-0224CDC279EF}`
  - System-level installation with centralized update management
- **macOS**: PKG installer deployment via MDM (Jamf/Intune)  
  - Bundle ID: `com.postmanlabs.enterprise.mac`
  - Administrative installation with managed configuration

#### Layer 2: Identity Provider & User Management
- **SAML Integration**: Corporate SSO (Okta, Azure AD, ADFS, generic SAML)
- **SCIM Provisioning**: Automated user and team provisioning from corporate directory
- **Just-in-Time Provisioning**: Dynamic user creation and team assignment based on directory attributes
- **Role-Based Access Control**: Integration with corporate roles and permissions

#### Layer 3: Domain & Organizational Control
- **Domain Capture**: Organizational control over postman.com domain access
- **Domain Verification**: DNS/file-based verification proving organizational ownership
- **Team Management**: Centralized control over team creation, membership, and permissions
- **Workspace Governance**: Administrative oversight of API collections, environments, and sensitive data

#### Layer 4: Enforcement Mechanisms (Required for Complete Control)

**Challenge:** Without enforcement, users can bypass enterprise controls by:
- Installing consumer Postman on personal devices and syncing corporate workspaces
- Using consumer Postman on managed devices to access personal/non-corporate teams
- Extracting API credentials and sensitive data outside organizational boundaries

**Enforcement Options:**

**Option A: Network-Level Blocking**
- Block consumer Postman domains at firewall/proxy
- **Pros**: Comprehensive blocking, no client-side components
- **Cons**: Requires corporate network/VPN; breaks when users work remotely; poor user experience with error messages

**Option B: Device-Level Blocking** 
- Use AppLocker/Configuration Profiles to prevent consumer Postman installation/execution
- **Pros**: Works regardless of network location
- **Cons**: Disruptive user experience; requires complex policy management; potential productivity impact

**Option C: IDP Device Trust + SAML Enforcement Daemon (Recommended)**
- **Complete Data Lockdown**: IDP device trust ensures only managed devices authenticate + SAML daemon ensures managed devices can only access corporate instance
- **Pros**: Best user experience; works anywhere; transparent operation; preserves app functionality; bidirectional enforcement (only managed devices in, only corporate instance accessible)
- **Cons**: Requires client-side component deployment and IDP device trust configuration
- **Implementation**: Corporate IDP device trust policies + SSL interception daemon with automatic redirect to corporate SAML flow

---

## 4. Implementation Plan

### 4.1 Phase 1: Foundation & Pilot (4-6 weeks)
**Scope:** Security team and select API development leads (20-30 users)

**Foundation Setup:**
1. **Identity Provider Configuration**: SAML integration with corporate IDP
2. **Domain Setup**: Postman Domain Capture configuration and verification  
3. **SCIM Integration**: Automated user provisioning from corporate directory
4. **Enterprise Application Deployment**: MSI/PKG deployment to pilot devices
5. **Administrative Controls**: Team creation, workspace setup, and governance policies

**Success Criteria:**
- All authentication flows through corporate SAML provider
- Users automatically provisioned with correct team memberships
- Enterprise applications successfully replace consumer installations
- Administrative visibility into all pilot API development activities

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

**Current Implementation Architecture:**
- **SSL-Terminating Proxy**: Standalone Python daemon with full HTTPS capability
- **Target Domain**: identity.getpostman.com (via hosts file modification to 127.0.0.1)
- **Listen Port**: 443 (HTTPS with automatic SSL certificate generation and trust installation)
- **Interception Paths**: `/login`, `/enterprise/login`, `/enterprise/login/authchooser`
- **Parameter Preservation**: auth_challenge, continue URLs, team identifiers maintained across redirects
- **SAML Redirect**: HTTP 302 redirects to configured corporate SAML identity provider
- **Transparent Proxy**: All non-authentication requests proxied to upstream with proper SNI handling

**Windows Service Deployment:**
```powershell
# Install as Windows service (requires Administrator)
.\service\windows\install-service.ps1 install

# Start service
.\service\windows\install-service.ps1 start

# Check status
.\service\windows\install-service.ps1 status

# Clear sessions before first run
.\service\windows\install-service.ps1 srefresh
```

**macOS Service Deployment:**
```bash
# Install as system daemon (requires sudo)
sudo ./service/macos/install-service.sh install

# Start daemon
sudo ./service/macos/install-service.sh start

# Check status
sudo ./service/macos/install-service.sh status

# Clear sessions before first run  
sudo ./service/macos/install-service.sh srefresh
```

**Configuration File (config/config.json):**
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

**Supported Identity Providers:**
- **Okta**: `https://identity.getpostman.com/sso/saml/init?team={team_name}`
- **Azure AD/ADFS**: `https://identity.getpostman.com/sso/saml/init?team={team_name}`
- **Generic SAML**: `https://identity.getpostman.com/sso/saml/init?team={team_name}`

**Device Trust Enforcement Mechanism:**
- Daemon must be running on device for authentication to succeed
- Hosts file redirection ensures requests cannot bypass daemon
- SSL certificate trust validation prevents simple proxy circumvention
- Session clearing ensures fresh authentication on daemon deployment
- Service monitoring and auto-restart prevents daemon termination bypass

**Session Management:**
```bash
# Clear all existing Postman sessions (run before daemon deployment)
python3 scripts/clear_postman_sessions.py

# This clears:
# - Browser cookies (Chrome, Firefox, Safari, Brave)
# - Postman application session files  
# - Postman Enterprise application session files
# - Automatically restarts affected applications
```

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