# SecuringAzWDefender&Sentinel

## Microsoft Defender for Cloud

Overview
    • Microsoft Defender for Cloud (formerly Azure Security Center)
    • A unified cloud-native application protection platform (CNAPP) in Azure
    • Provides:
        ○ CSPM (Cloud Security Posture Management)
        ○ Workload Protection for servers, containers, databases, and more
    • Monitors:
        ○ Azure resources
        ○ On-premises infrastructure (via Azure Arc agent)
        ○ Multi-cloud platforms (AWS, GCP)
        ○ GitHub repositories
        ○ Microsoft 365 services

Capabilities
    • Continuous security assessment across environments
    • Flags misconfigurations and non-compliant resources
    • Provides actionable recommendations with guided remediation
    • Detects threats using Microsoft threat intelligence
    • Offers auto-provisioning of agents for supported services
    • Integrates with Logic Apps for automated incident response

Agent Requirements
    • Azure resources: monitored natively
    • On-prem or AWS/GCP VMs:
        ○ Must install Azure Arc agent
        ○ Enables telemetry and policy enforcement
    • Arc onboarding is needed before Defender coverage applies

Multi-Cloud Onboarding
    • To onboard AWS:
        ○ Provide:
            § AWS Account ID
            § Azure Subscription, Resource Group, and Location
            § Connector name
        ○ Creates a Defender connector resource in Azure
    • Similar setup applies to GCP integration

Recommendations View
    • Findings sorted by severity:
        ○ High, Medium, Low
    • Each finding includes:
        ○ Unhealthy resource count
        ○ Remediation options:
            § Manual fix
            § One-click Fix
            § Launch Logic App
            § Exempt for acceptable risks

Sample Recommendations
    • Protect internet-facing VMs with NSGs
    • Enable Log Analytics agent
    • Restrict open NSG ports
    • Install endpoint protection
    • Enable:
        ○ Microsoft Defender for Containers
        ○ Microsoft Defender for Resource Manager
        ○ Microsoft Defender for App Service
        ○ Microsoft Defender for Key Vault
        ○ Secure transfer on Storage Accounts

Compliance Standards (Policy Initiatives)
    • Defender for Cloud can evaluate compliance against:
        ○ Microsoft Cloud Security Benchmark (MCSB)
        ○ PCI-DSS
        ○ ISO 27001
        ○ SOC TSP
    • Policies can be enabled or disabled
    • Defender assigns compliance scores per standard

Vulnerability Assessment Integration
    • Built-in vulnerability scanner (powered by Qualys)
    • Assesses:
        ○ Windows and Linux VMs
        ○ Container images (via Defender for Containers)
    • Displays:
        ○ Description of vulnerability
        ○ Severity
        ○ Remediation steps
        ○ Affected resources
        ○ Fix button / Exemption / Logic App trigger

Licensing
    • Free Tier:
        ○ Security posture management
        ○ Recommendations
    • Standard Tier (paid):
        ○ Threat protection
        ○ Alerts
        ○ Vulnerability assessments
        ○ Regulatory compliance dashboards

Best Practices (AZ-500)
    • Enable Microsoft Defender plans per resource type
    • Use Management Groups for Defender policy inheritance
    • Connect Arc-enabled servers for hybrid security posture
    • Regularly review compliance dashboard and threat alerts
    • Leverage auto-provisioning settings to enforce agent deployment
    • Use Logic Apps for automated remediation workflows

## Managing Microsoft Defender for Cloud for Azure Servers

Managing Microsoft Defender for Cloud for Azure Servers
🛡 Purpose of Defender for Cloud
    • Detects vulnerabilities, threats, and misconfigurations
    • Applies continuous compliance checks against security benchmarks
    • Not limited to Azure: supports AWS, GCP, on-prem via Azure Arc

⚙️ Storage Account Integration
    • Navigate: Storage Account → Security + Networking → Microsoft Defender for Cloud
    • Status: Shows if Defender for Storage is ON
    • Upgrade link available: Adds malware scanning + sensitive data discovery
Recommendations (with severity):
    • Use Private Link (Medium)
    • Restrict access via VNet rules
    • Disallow public access
    • Tactics/Techniques mapping (e.g. “Initial Access” for public exposure)
    • Remediation:
        ○ Quick Fix Logic: set allowBlobPublicAccess to false
        ○ Trigger Logic App for custom fixes
        ○ Assign issue to an owner with due date
        ○ Use Exempt if not applicable
        ○ View or assign policy definitions (e.g. deny effect to block future insecure configs)

⚙️ Virtual Machine Integration
    • Navigate: VM → Settings → Microsoft Defender for Cloud
    • Displays:
        ○ of Recommendations
        ○ of Security Alerts
        ○ Defender for Servers status (e.g. ON)
        ○ Enable Just-in-Time VM Access (JIT): Reduces exposure window for admin ports
Example Recommendations:
    • High:
        ○ Enable Azure Disk Encryption
        ○ Encrypt temp disks + caches
        ○ Ensure updates check enabled
    • Medium/Low:
        ○ Enable Azure Backup
        ○ Install Log Analytics Agent
Actions:
    • View Remediation steps (manual links or auto-fix)
    • Use Take Action button to jump to config
    • View Security Incidents:
        ○ Show IPs, flags (malicious/unusual), timestamps

🧭 Central Console: Defender for Cloud
    • Access via Search → Defender for Cloud
    • Overview:
        ○ Security score (e.g. 36%)
        ○ Cross-cloud monitoring (AWS, GCP)
    • Regulatory Compliance:
        ○ Microsoft Cloud Security Benchmark (e.g. 43/62 passed)
        ○ Drill into controls (e.g. PA-1: Privileged access separation)

🔍 Additional Navigation Panels
    • Security alerts
    • Inventory: Lists all resources (VMs, Storage, VNETs)
    • Add non-Azure servers
    • Security posture
    • Workload protections

AZ-500 Key Focus Areas
    • Defender plans: for Storage, for Servers, for App Services, etc.
    • Automation: Logic Apps, JIT, policy assignment
    • Threat detection, alert handling, and recommendation management
    • Cross-cloud + on-prem integration via Azure Arc
    • Understanding built-in policies and exemptions
    • Monitoring compliance with Microsoft Defender for Cloud dashboard
