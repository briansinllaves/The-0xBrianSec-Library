# Securing Azure with Defender & Sentinel

## Microsoft Defender for Cloud

### Overview

Microsoft Defender for Cloud (formerly Azure Security Center) is a unified cloud-native application protection platform (CNAPP) in Azure.

**Provides:**
- CSPM (Cloud Security Posture Management)
- Workload Protection for servers, containers, databases, and more

**Monitors:**
- Azure resources
- On-premises infrastructure (via Azure Arc agent)
- Multi-cloud platforms (AWS, GCP)
- GitHub repositories
- Microsoft 365 services

### Capabilities

- Continuous security assessment across environments
- Flags misconfigurations and non-compliant resources
- Provides actionable recommendations with guided remediation
- Detects threats using Microsoft threat intelligence
- Offers auto-provisioning of agents for supported services
- Integrates with Logic Apps for automated incident response

### Agent Requirements

| Environment | Requirements |
|-------------|-------------|
| Azure resources | Monitored natively |
| On-prem or AWS/GCP VMs | Must install Azure Arc agent - enables telemetry and policy enforcement |

{% hint style="info" %}
Arc onboarding is needed before Defender coverage applies
{% endhint %}

### Multi-Cloud Onboarding

**To onboard AWS:**
- Provide:
  - AWS Account ID
  - Azure Subscription, Resource Group, and Location
  - Connector name
- Creates a Defender connector resource in Azure
- Similar setup applies to GCP integration

### Recommendations View

**Findings sorted by severity:** High, Medium, Low

**Each finding includes:**
- Unhealthy resource count
- Remediation options:
  - Manual fix
  - One-click Fix
  - Launch Logic App
  - Exempt for acceptable risks

### Sample Recommendations

- Protect internet-facing VMs with NSGs
- Enable Log Analytics agent
- Restrict open NSG ports
- Install endpoint protection
- Enable:
  - Microsoft Defender for Containers
  - Microsoft Defender for Resource Manager
  - Microsoft Defender for App Service
  - Microsoft Defender for Key Vault
  - Secure transfer on Storage Accounts

### Compliance Standards (Policy Initiatives)

Defender for Cloud can evaluate compliance against:
- Microsoft Cloud Security Benchmark (MCSB)
- PCI-DSS
- ISO 27001
- SOC TSP

Policies can be enabled or disabled. Defender assigns compliance scores per standard.

### Vulnerability Assessment Integration

**Built-in vulnerability scanner (powered by Qualys)**

**Assesses:**
- Windows and Linux VMs
- Container images (via Defender for Containers)

**Displays:**
- Description of vulnerability
- Severity
- Remediation steps
- Affected resources
- Fix button / Exemption / Logic App trigger

### Licensing

| Tier | Features |
|------|----------|
| **Free Tier** | Security posture management, Recommendations |
| **Standard Tier (paid)** | Threat protection, Alerts, Vulnerability assessments, Regulatory compliance dashboards |

### Best Practices (AZ-500)

- Enable Microsoft Defender plans per resource type
- Use Management Groups for Defender policy inheritance
- Connect Arc-enabled servers for hybrid security posture
- Regularly review compliance dashboard and threat alerts
- Leverage auto-provisioning settings to enforce agent deployment
- Use Logic Apps for automated remediation workflows

---

## Managing Microsoft Defender for Cloud for Azure Servers

### Purpose of Defender for Cloud

🛡️ **Detects:**
- Vulnerabilities, threats, and misconfigurations
- Applies continuous compliance checks against security benchmarks
- Not limited to Azure: supports AWS, GCP, on-prem via Azure Arc

### Storage Account Integration

**Navigate:** `Storage Account → Security + Networking → Microsoft Defender for Cloud`

**Shows:**
- Status: If Defender for Storage is ON
- Upgrade link available: Adds malware scanning + sensitive data discovery

**Recommendations (with severity):**
- Use Private Link (Medium)
- Restrict access via VNet rules
- Disallow public access
- Tactics/Techniques mapping (e.g. "Initial Access" for public exposure)

**Remediation options:**
- Quick Fix Logic: set `allowBlobPublicAccess` to false
- Trigger Logic App for custom fixes
- Assign issue to an owner with due date
- Use Exempt if not applicable
- View or assign policy definitions (e.g. deny effect to block future insecure configs)

### Virtual Machine Integration

**Navigate:** `VM → Settings → Microsoft Defender for Cloud`

**Displays:**
- Number of Recommendations
- Number of Security Alerts
- Defender for Servers status (e.g. ON)
- Enable Just-in-Time VM Access (JIT): Reduces exposure window for admin ports

**Example Recommendations:**

{% tabs %}
{% tab title="High" %}
- Enable Azure Disk Encryption
- Encrypt temp disks + caches
- Ensure updates check enabled
{% endtab %}

{% tab title="Medium/Low" %}
- Enable Azure Backup
- Install Log Analytics Agent
{% endtab %}
{% endtabs %}

**Actions:**
- View Remediation steps (manual links or auto-fix)
- Use Take Action button to jump to config
- View Security Incidents: Show IPs, flags (malicious/unusual), timestamps

### Central Console: Defender for Cloud

**Access:** `Search → Defender for Cloud`

**Overview:**
- Security score (e.g. 36%)
- Cross-cloud monitoring (AWS, GCP)

**Regulatory Compliance:**
- Microsoft Cloud Security Benchmark (e.g. 43/62 passed)
- Drill into controls (e.g. PA-1: Privileged access separation)

### Additional Navigation Panels

- Security alerts
- Inventory: Lists all resources (VMs, Storage, VNETs)
- Add non-Azure servers
- Security posture
- Workload protections

### AZ-500 Key Focus Areas

- Defender plans: for Storage, for Servers, for App Services, etc.
- Automation: Logic Apps, JIT, policy assignment
- Threat detection, alert handling, and recommendation management
- Cross-cloud + on-prem integration via Azure Arc
- Understanding built-in policies and exemptions
- Monitoring compliance with Microsoft Defender for Cloud dashboard

---

## Managing Microsoft Defender for Cloud for Databases

### Purpose

🎯 **Provide threat protection and vulnerability assessment for Azure and non-Azure databases**

**Detects suspicious activity like:**
- SQL injection
- Brute-force login attempts
- Unauthorized data access

**Scans configuration for:**
- Security misconfigurations
- Compliance gaps
- Missing best practices

**Integrates with:** AWS, GCP, on-prem databases using Azure Arc

### Enabling Defender for Databases

1. Go to `Microsoft Defender for Cloud → Environment Settings`
2. Choose Management Group or your Azure Subscription
3. Click Defender plans
4. Scroll to Database section
5. Toggle Defender ON, then click Select types:
   - Azure SQL Database ✅
   - SQL servers on machines (on-prem or IaaS)
   - Azure Cosmos DB
   - Open-source relational DBs (e.g., MySQL, PostgreSQL)
6. Save configuration

### Alerts & Automation

**Email Notifications:**
- Owner role notified by default
- Can add other roles (e.g., Contributor) or custom emails

**Workflow Automation:**
- Define triggers (e.g., High-severity alert)
- Run Logic Apps to:
  - Quarantine resources
  - Auto-remediate issues
  - Send alerts to SIEM or ticketing systems

### Creating a Secure SQL Database (With Defender)

1. `Portal → Create Resource → Azure SQL → Single Database`
2. **Configure:**
   - Resource group
   - Database name (e.g., app1sqldb1)
   - New/existing SQL Server
3. **Authentication:**
   - SQL Authentication (Username + Password)
   - Optional: Azure AD integration
4. **Networking:**
   - Use Private endpoint
   - Avoid public IP exposure
   - Assign to VNet/Subnet
5. **Security Tab:**
   - Toggle Microsoft Defender for SQL → "Start Free Trial" or "Enable"
6. **Proceed with:**
   - Sample data
   - Tagging
   - Review + Create

### Post-Deployment Monitoring

**Navigate:** `SQL Database → Microsoft Defender for Cloud`

**Under Security, view:**
- Recommendations (e.g., restrict public access)
- Severity (High, Medium, Low)
- Tactics/Techniques (e.g., Initial Access)

**Use:**
- Quick Fix (auto sets `allowBlobPublicAccess`: false)
- Assign Owner for follow-up
- Exempt (optional, if justified)
- Open View Policy Definition for granular control
- Use Deny Policy Effect to prevent insecure deployments

### Recommendation Examples

- "Public access should be disabled"
- "Use private endpoints"
- "Enable advanced threat protection"
- "Encrypt data at rest and in transit"
- "Install vulnerability assessment extensions"

### Additional Details

- Defender auto-assesses new + existing databases
- Use View all recommendations to see tenant-wide security posture
- Supports compliance monitoring (e.g., PCI DSS, ISO 27001, SOC TSP)
- Defender checks apply regardless of deployment method (manual, ARM, Terraform)

### Key AZ-500 Concepts

- Microsoft Defender for SQL is part of Defender for Cloud
- Protects both PaaS (Azure SQL DB) and IaaS-hosted SQL (via Arc agent)
- Enables threat detection, policy assignment, and remediation workflows
- Best practice: deploy using Private endpoints, enable Defender, and assign remediation automation

---

## Viewing Microsoft Cloud Vulnerability Scan Results

### Purpose

Microsoft Defender for Cloud scans Azure, AWS, GCP, and on-premises (via Azure Arc) for:
- Vulnerabilities
- Misconfigurations
- Indicators of compromise (IoC)

### Access Methods

View scan results at:
- Individual resource level (e.g., VM, Storage Account)
- Global view via Defender for Cloud dashboard

### Resource-Level Scan (Example: Virtual Machine)

**Navigate:** `VM > Defender for Cloud`
- View individual recommendations
- Severity levels (High, Medium, Low)
- Specific findings like "Install endpoint protection," "Encrypt disks"

### Global Security Posture View

**From Portal:** `Search Defender, open Microsoft Defender for Cloud`

**Overview:**
- Unified view of security recommendations across Azure and linked AWS/GCP accounts
- Security Score
- Assessed Resources Count

### Environment Settings

**View connected environments:**
- Azure subscriptions
- External accounts (AWS/GCP)
- Inventory includes EC2 instances, on-prem VMs, Azure resources

### Inventory View

**Filter by:**
- Cloud provider (Azure, AWS, GCP)
- Resource Type (e.g., EC2, VM, Storage)

**Drill down for:**
- Installed applications
- Security recommendations
- Affected resources

**Export to CSV** for external analysis (e.g., Excel filtering by resource type)

### Regulatory Compliance

**Standards:**
- Microsoft Cloud Security Benchmark
- PCI DSS 3.2.1
- ISO 27001
- SOC TSP

**View and download compliance reports:**
- Azure Shared Responsibility Matrix
- Attestation of Compliance PDFs

### Key Actions

- Click Recommendations to view/fix misconfigurations
- Use Audit Reports for compliance verification
- Monitor AWS/GCP VMs like native Azure VMs
- Download and manipulate CSV reports for documentation or audits

---

## Security Information and Event Management (SIEM) and Azure Sentinel

### SIEM Overview

**SIEM = Security Information and Event Management**

**Purpose:** Centralized threat detection, analysis, and response

Consolidates and correlates logs from multiple sources to detect anomalies, threats, and breaches

**Core Functions:**
- Event aggregation (collects from many systems)
- Correlation of events (identifies patterns)
- Real-time alerting and dashboards
- Forensic investigation support
- Compliance reporting

### SOAR Overview

**SOAR = Security Orchestration, Automation, and Response**

Extends SIEM with automated remediation and workflow orchestration

**Can:**
- Run playbooks in response to alerts
- Integrate with ticketing, email, or IP blocking systems
- Allow human-in-the-loop or full automation

### Microsoft Sentinel

Cloud-native SIEM + SOAR in Azure designed to analyze security data at scale with built-in AI/ML

**Integrates with:**
- Microsoft Defender for Cloud
- Microsoft 365 Defender
- Azure AD
- 3rd-party data sources (e.g., AWS, Barracuda, Cisco, Fortinet)

### Core Components

#### 1. Log Analytics Workspace
- Foundation for Sentinel
- All ingested data is stored here
- Supports KQL (Kusto Query Language) for queries

#### 2. Data Connectors
**Prebuilt integrations for data ingestion**

Examples:
- **Microsoft services:** Azure AD, Defender, Office 365
- **3rd-party:** AWS CloudTrail, Palo Alto, Cisco ASA, Fortinet
- **Syslog:** Generic log source for Linux/UNIX
- Custom connectors supported via REST API or Logic Apps

#### 3. Analytics Rules
Use built-in or custom rules to generate incidents from ingested data

**Detect:**
- Unusual login behavior
- Port scanning
- Lateral movement
- Exfiltration attempts

#### 4. Incidents
**Result of triggered analytics rules**

**Contain:**
- Timeline of related events
- Entities involved (IP, user, hostname)
- Severity & status (New, In Progress, Closed)

#### 5. Workbooks
**Dashboards for visualization**

Customizable per scenario:
- Threat hunting
- Compliance reporting
- SOC operations

#### 6. Playbooks (SOAR)
**Based on Azure Logic Apps**

Respond automatically to incidents

**Examples:**
- Disable user in Azure AD
- Block IP in NSG
- Send email/slack alert
- Create ServiceNow ticket

#### 7. Hunting
- Manual threat investigation using KQL
- Used by SOC analysts
- Includes built-in hunting queries (MITRE ATT&CK mapped)

#### 8. Entity Behavior Analytics (UEBA)
**Identifies behavioral anomalies per user or host**

**Detects:**
- Impossible travel
- Login location anomalies
- Abnormal file access

#### 9. Watchlists
- External lists imported into Sentinel (IP blacklist, HR termination list, etc.)
- Referenced in detection rules or queries

### Use Cases

**Ingest and correlate:**
- Azure VM logs, NSG flow logs
- AWS CloudTrail events
- Microsoft 365 login logs

**Detect:** brute force, phishing, or insider threats

**Auto-respond:**
- Quarantine VM
- Disable account
- Block IP on perimeter firewall

### Integration Examples

| Source | Method | Use In Sentinel |
|--------|--------|-----------------|
| Azure AD logs | Built-in connector | Detect suspicious logins |
| AWS CloudTrail | Data connector + API keys | Monitor cloud activity |
| Linux servers | Syslog agent to Log Analytics | Monitor SSH activity, sudo, etc. |
| On-prem firewall | Common Event Format (CEF) agent | Ingest traffic logs, threat alerts |
| Defender for Endpoint | Native integration | Get device-level threats |

### Best Practices for AZ-500

- Always use Log Analytics Workspace in the same region as resources
- Enable MFA and monitor failed login attempts
- Create custom analytics rules to suit your org
- Use built-in templates for connectors and rules first
- Configure Logic App-based Playbooks for SOAR
- Use workbooks for executive dashboards
- Regularly review incident timeline and severity
- Enable UEBA for behavior-based detections

### Microsoft Sentinel vs Other SIEMs

| Feature | Microsoft Sentinel | Traditional SIEMs (e.g., Splunk) |
|---------|-------------------|----------------------------------|
| Deployment | Fully cloud-native | On-prem or hybrid |
| Data ingestion | Azure-native & 3rd-party | Depends on integration effort |
| Scaling | Auto-scale with Azure | Manual provisioning |
| Pricing | Pay-as-you-go (GB ingested) | Often license-based |
| SOAR | Built-in (Logic Apps) | May need separate product/module |

---

## Managing Azure Sentinel Connectors and Alerts

### Overview

- Microsoft Sentinel must be attached to a Log Analytics workspace
- Workspaces store ingested data, logs, incidents, alerts, and enable hunting with KQL
- Data Connectors bring in telemetry from diverse sources
- Alerts can trigger playbooks, notifications, or manual/automated incident response

### Accessing Sentinel

- Go to `Azure Portal > Search: "Sentinel"`
- If not set up, create a Log Analytics Workspace
- Attach Sentinel to it via "Add"

### Data Connectors

**Found under:** `Configuration > Data connectors`

100+ built-in connectors for:
- **Azure services:** AAD, Key Vault, NSG, Storage, etc.
- **Third-party sources:** AWS, Cisco ASA, Barracuda, Fortinet, Palo Alto
- **On-prem devices:** via Syslog, CEF (Common Event Format), REST APIs

**Examples:**

| Connector Source | Data Types Ingested | Prerequisites |
|------------------|-------------------|---------------|
| Azure Active Directory | Sign-in logs, audit logs, risky users | Azure AD diagnostic settings + proper roles (Global Admin) |
| Azure Storage Account | Blob read/write/delete logs | Configure diagnostic settings → Log Analytics |
| NSG (Network Security Group) | Flow logs | Assign Azure Policy to send diagnostics to workspace |
| Cisco Meraki | Firewall/Security device logs via Syslog | Configure syslog export to Log Analytics |

{% hint style="warning" %}
After free data ingestion quota (5GB/day as of writing), costs apply per GB, so only ingest what's needed
{% endhint %}

### Steps to Connect a Data Source (e.g., Azure AD)

1. Go to `Sentinel > Data Connectors`
2. Click on source (e.g., Azure Active Directory)
3. Review prerequisites (roles, diagnostics)
4. Enable necessary logs (Sign-In, Audit, Risky Users, etc.)
5. Apply changes → Sentinel begins ingesting logs

### Custom Diagnostic Settings for Storage

1. Open Azure Storage Account
2. Go to `Monitoring > Diagnostic Settings`
3. Click Add Diagnostic Setting
4. Choose Log Analytics workspace destination
5. Enable relevant categories (Blob logs, etc.)
6. Save

### NSG Logs with Azure Policy

Some connectors (like NSG) require Azure Policy Assignment

**Steps:**
1. Launch Policy Wizard from connector page
2. Assign to subscription or resource group
3. Select Log Analytics workspace
4. Enable remediation task
5. Create assignment → NSG logs sent to Sentinel

### Handling Third-Party Devices

**E.g., Cisco Meraki**
- Needs Syslog configured
- Sentinel provides instructions for log forwarding
- Use Syslog/CEF collector VMs if needed

### Sentinel Automation & Alerts

**Found under:** `Automation > Rules / Playbooks`

**Trigger response actions when:**
- Analytics rules fire
- Specific incidents or thresholds are met

**Actions can include:**
- Send email/Teams/Slack alert
- Call Logic App playbook
- Assign incident owner (e.g., Codey Blackwell)
- Disable user or block IP

### Hunting and Queries

**Go to Hunting blade**

Use KQL to:
- Search for indicators of compromise (IoCs)
- Investigate known campaigns (e.g., WannaCry DNS domains)

Select a query > Run selected query > View results

### Best Practices

- Regularly review connected connectors and data cost
- Use filters to find connectors by vendor or type
- Automate common alert responses with playbooks
- Test queries in Hunting before creating new detection rules
- Monitor ingestion costs post-trial and refine logs ingested
- Review incident severity, assign owners, and triage frequently

### AZ-500 Exam Tips

- Know how to connect services to Sentinel using diagnostic settings
- Understand prerequisites for major connectors like Azure AD, NSG
- Be able to configure alert automation using Logic Apps
- Be familiar with role requirements: Global Admin, Security Admin
- Understand how to manage ingestion from on-prem (Syslog/CEF) and third-party

---

## Threat Modeling with the Microsoft Threat Modeling Tool

### Purpose

Helps IT admins, security engineers, developers visualize and secure app/data flows

- Used to identify, analyze, and mitigate threats early in the development lifecycle
- Free tool from Microsoft, designed for Windows

### Setup

- Download from Microsoft's official page
- Requirements: Windows 10 Anniversary Update+, .NET 4.7.1+
- Install via one-click setup
- Launch the app and agree to license terms

### Core Features

- Supports Azure-specific templates (e.g., Azure Storage, Web Apps)
- Drag-and-drop UI with components like:
  - Azure services (Storage, Web Apps, SQL)
  - Clients (Web browser, Mobile client, IoT)
  - Data flows (e.g., HTTP requests)

### Workflow

**Step-by-step:**
1. **Open a template or start a new model**
   - Example: "Azure Cloud Services" template
2. **Add components from the Stencils pane:**
   - E.g., Azure Storage + Web Application + Request
3. **Configure Properties:**
   - Azure Storage: type = Blob, enforce HTTPS
   - Web App: type = MVC or Web Forms
   - Data Flow: customize method (GET/POST), transport protocol
4. **Click View > Analysis View** to run threat analysis
   - Tool lists identified threats automatically
   - Example threat: Unauthorized access to Azure Storage

### Threat Analysis Output

Each threat includes:

| Field | Description |
|-------|-------------|
| **Threat Name** | E.g., Unauthorized access due to weak controls |
| **Description** | Explains how attacker might exploit the flaw |
| **Mitigations** | E.g., Use SAS (Shared Access Signature), enforce HTTPS, set RBAC properly |

### Model Management

- Save models (e.g., SimpleAzureWebApp.tms)
- Switch between Design View and Analysis View
- Use File > Save or File > Export for documentation or audit trails

### Advanced Modeling

- Add more entities: Web Browser, Mobile Client, IoT Device, CRM
- Mobile Client Technologies include:
  - Android, iOS, CRM Outlook Client, Dynamics Mobile
- Define relationships and trust boundaries visually

### Security Use Cases

| Use Case | How Tool Helps |
|----------|----------------|
| Azure Web App accessing Storage | Visualize flow, enforce HTTPS, restrict blob access |
| Client-server authentication flows | Model session tokens, credential storage, authorization gaps |
| IoT integration with cloud services | Analyze data integrity and communication exposure |
| Web APIs & third-party service usage | Spot over-permissive calls or weak auth flows |

### Benefits for Azure/AZ-500

- Visualize attack surface of Azure-hosted apps/services
- Identify issues before deployment
- Understand use of mitigations like:
  - Shared Access Signatures
  - Role-Based Access Control (RBAC)
  - Network Security Group (NSG) limitations
- Prepares for secure design questions on AZ-500

### Best Practices

- Use pre-built templates for cloud services when available
- Always enforce HTTPS and proper access control in diagrams
- Run analysis after all flows and assets are mapped
- Document and export threat models for audit or review
- Incorporate threat modeling into DevSecOps pipelines

---

## Managing Azure VM Updates

### Why It Matters

- Ensures critical security patches are applied
- Prevents exploitation from unpatched OS vulnerabilities
- Must balance security with stability/testing

### Two Ways to Manage Updates

| Method | Description |
|--------|-------------|
| **Per-VM Manual** | Through individual VM settings in Azure portal |
| **Automation Account** | Centralized update management via Log Analytics & Update Management |

### Manual Updates (Per VM)

**Steps:**
1. Go to Virtual machines in Azure Portal
2. Select a VM (Linux or Windows)
3. In left nav: under Operations, click Updates
4. Click Check for updates (if needed)

**Options:**
- **One-time update:** Apply now
- **Classifications:** Filter by Security, Critical, etc.
- **View update list by:**
  - Name/version
  - Category
  - Count (e.g., 86 total updates, 60 critical)
- **Reboot options:**
  - Reboot if required
  - Never reboot
  - Always reboot
- **Maintenance window:** Duration (in minutes) Azure has to apply updates

**Scheduling:**
You can also click Schedule update for recurring deployments

### Automation Account + Update Management (Recommended at scale)

#### Create Automation Account

1. `Azure Portal → search Automation Account → Create`
2. Fill in:
   - Name (e.g., automation1)
   - Region (e.g., East US)
   - Identity: System-assigned
   - Public access allowed
   - No Tags (optional)
3. Click Create → Go to resource

#### Enable Update Management

In the Automation Account:
1. Click Update Management in left nav
2. Link to a Log Analytics Workspace
   - Can use existing or create new
3. Click Enable
4. After enabling, refresh the screen

#### Add Virtual Machines

- Click Add Azure VMs
- Select VMs to monitor (Windows/Linux)
- Click Enable
- Can also add non-Azure machines via Azure ARC

### Schedule Update Deployment

After VMs are added:
- Click Schedule update deployment
- Options include:
  - Update classification (Security, Critical, etc.)
  - Include/Exclude specific updates (e.g., by KB ID)
  - Reboot settings
  - Maintenance window
  - Recurring schedule

### Benefits of Using Automation Account

| Feature | Benefit |
|---------|---------|
| **Centralized control** | Manage updates for 100s of VMs from one place |
| **Reporting** | See compliance and missing updates in Log Analytics |
| **Supports hybrid environments** | Works for Azure VMs + on-premises via ARC |
| **Integration with Security** | Helps meet compliance/audit standards (e.g., PCI, NIST) |

### Best Practices

- Always test updates in dev/staging before prod
- Schedule updates during maintenance windows
- Set "Reboot if required" for safer automation
- Monitor compliance using Log Analytics queries

### AZ-500 Relevance

Understanding Update Management is key to:
- Maintaining secure posture
- Managing hybrid cloud security
- Automating remediation as part of SOAR

May be tested on:
- VM update compliance
- Automation Account setup
- Linking Log Analytics