# Monitoring Az Services

## Working with Action Groups

1. Purpose of Action Groups
    • Action Groups define how Azure responds when an alert rule triggers.
    • They are reusable notification/action bundles used by Azure Monitor and security alerting systems.
    • Used in scenarios such as:
        ○ Security incidents (e.g., unauthorized access, resource abuse).
        ○ Performance degradation (e.g., high CPU from malware).
        ○ Compliance violations (e.g., untagged resources, disabled firewalls).

2. Key Components of an Action Group
Each action group can have notifications and automated actions:
a. Notification Types
    • Email
    • SMS
    • Push notifications (Azure Mobile App)
    • Voice call
b. Action Types
    • Automation Runbook – triggers remediation scripts.
    • Logic App – complex workflows and integrations.
    • Azure Function – custom code execution.
    • Webhooks / Secure Webhooks – external system integration.
    • ITSM – creates tickets in ServiceNow or other ITSM tools.
    • Event Hub – stream alert data to SIEM/SOAR platforms.

3. Creating an Action Group
Steps to create in the Azure Portal:
    1. Azure Monitor > Alerts > Action Groups > Create
    2. Basics:
        ○ Name, Region, Resource Group
        ○ Note: Action Groups are global, not tied to a specific resource.
    3. Notifications:
        ○ Add one or more notification methods (e.g., email and SMS).
    4. Actions:
        ○ Choose optional automation: runbooks, Logic Apps, etc.
    5. Tags (optional):
        ○ Useful for tracking in cost management or resource management.
    6. Review + Create

4. Using Action Groups in Alert Rules
a. Alert Rule Setup
    • Navigate to any resource (e.g., VM, App Service).
    • Go to Monitoring > Alerts > Create Alert Rule.
    • Define:
        ○ Scope (resource)
        ○ Condition (signal + threshold, e.g., CPU > 80%)
        ○ Action Group (create new or select existing)
        ○ Alert Details (name, severity, description)
b. Evaluation Frequency
    • Example:
        ○ Check every 1 minute
        ○ Lookback period: 5 minutes
c. Alert Logic Examples
    • Web App HTTP 5xx errors > 1
    • VM CPU % > 80
    • Firewall rule deleted (via activity logs)

5. Integration with Security & Compliance
    • Azure Security Center/Defender for Cloud integrates with Action Groups to notify on:
        ○ Regulatory compliance issues
        ○ Just-in-Time VM access requests
        ○ Threat detection alerts
    • Use Logic Apps for advanced incident response (e.g., isolate VM, disable account).

6. Managing Action Groups Across Resources
    • Action groups are reusable across:
        ○ VMs, App Services, Key Vaults, SQL, Cosmos DB, Storage
    • Central visibility under:
Azure Monitor > Alerts > Action Groups
    • Recommended to use consistent naming conventions (e.g., SecOps-Notify, AutoRemediate-Critical).

7. Exam-Relevant Notes
    • Action groups can be global and are NOT resource-specific.
    • Alert rules use action groups to define notification + response.
    • Multiple action groups can be attached to one alert rule.
    • Secure webhook uses OAuth2 authentication (for secure external calls).
    • Tags help classify and organize action groups but are not mandatory.
    • Understand integration with:
        ○ Activity Logs: Alert on create/delete resource events
        ○ Log Analytics: Custom queries for alert conditions (Kusto query language)

## Configuring Alert Notification

1. Purpose
    • Detect abnormal or risky conditions in Azure resources (e.g., CPU spikes, network anomalies, service failures).
    • Trigger notifications or automated response actions.
    • Enhance visibility, response, and compliance with operational and security events.

2. Access Azure Monitor
    • Go to Azure Portal > Monitor
    • Core areas:
        ○ Overview
        ○ Alerts
        ○ Metrics
        ○ Activity Log
        ○ Insights (VMs, Apps, Containers, Key Vaults, etc.)

3. Enable VM Monitoring
    • Monitor > Virtual Machines
    • Use Configure Insights:
        ○ Chooses Azure Monitor Agent (default)
        ○ Applies Data Collection Rule (DCR)
        ○ Monitored VMs show up under "Monitored"; others under "Not Monitored"
    ⚠️ VM must be powered on to configure insights.

4. Create an Alert Rule
Steps:
    1. Scope – select resource (e.g., Linux1)
    2. Condition – define alert logic
Example:
        ○ Signal: Percentage CPU
        ○ Aggregation: Average
        ○ Operator: >
        ○ Threshold: 80% (or lower to test)
    3. Evaluation Period:
        ○ Frequency: every 1 min
        ○ Lookback: 5 mins
    4. Action Groups – select one or more
    5. Details – name, severity (0–4), description
    6. Tags – optional, for filtering and cost tracking
    7. Review + Create

5. Edit Alert Rule (Post-Creation)
    • Go to Alerts > Alert Rules
    • Click existing rule (e.g., Linux1CPU)
    • Use Edit to:
        ○ Add/remove action groups
        ○ Change condition thresholds
        ○ Modify alert logic

6. Create Additional Alert Rule (New Metric)
    • Example:
        ○ Signal: Network In Total
        ○ Threshold: > 500 MB
        ○ Purpose: Detect abnormal data transfer
    • Reuse existing action groups (TextAdmins, EmailAdmins)

7. Create Action Groups
Example: EmailAdmins
    1. Go to Monitor > Alerts > Action Groups > Create
    2. Basics: Name, region, resource group
    3. Notifications:
        ○ Type: Email/SMS/Push/Voice
        ○ Add email (gets "welcome" message from Azure)
    4. Actions (optional):
        ○ Skip or add: Runbook, Logic App, Azure Function, Webhook
    5. Enable Common Alert Schema (for SIEM/SOAR compatibility)
    6. Review + Create
    🔁 Action groups are global, reusable across alert rules and resources.

8. Use Multiple Action Groups
    • Add more than one group to a single alert rule.
    • Example:
        ○ TextAdmins (SMS)
        ○ EmailAdmins (Email only)
    • Flexibility in who gets notified and how.

9. How Notifications Are Sent
    • Email: Confirmation + alert trigger
    • SMS: Short alert summary (e.g., “Sev3 alert: Linux1CPU”)
    • Azure App: Push notification
    • Voice: Robo-call with alert message

10. Best Practices (AZ-500 Specific)
    • Use descriptive alert names (e.g., Linux1CPUThreshold, App1-HTTP-Errors).
    • Group alerts by severity to match response SLAs.
    • Use tags to track alerting rules by owner, environment, or business unit.
    • Enable Common Alert Schema for uniform formatting across tools.
    • Integrate with:
        ○ Log Analytics for custom query-based alerts
        ○ Event Hubs for SIEM ingestion
        ○ Logic Apps for automated remediation
        ○ ITSM connectors for ticket creation (e.g., ServiceNow)
 

## Enabling Web App Application Insights

1. Purpose of Application Insights
    • Deep performance monitoring, availability checks, and usage analytics for web apps.
    • Detects failures, performance bottlenecks, and user behavior patterns.
    • Supports custom telemetry via SDK integration.

2. Application Insights Supported Platforms
    • Works best with:
        ○ .NET, .NET Core
        ○ Node.js, Java
    • Not available for:
        ○ Some Linux-based runtime stacks (e.g., Python)
        ○ You must use supported runtimes for full integration.

3. Deploying a Web App with Application Insights
a. Go to:
Azure Portal > App Services > Create
b. Basic Setup
    • Name: e.g., samplenewandwonderfulapp
    • Platform: Windows
    • Stack: .NET Core or similar
    • Region: Same as Application Insights (or let Azure create new)
c. Monitoring Tab
    • Enable Application Insights: Yes (default for supported stacks)
    • Select AI resource:
        ○ Use existing
        ○ Or let Azure create a new resource for this web app
d. Finalize
    • Click Review + Create, then Create

4. After Deployment
a. Navigate to the Web App
    • In left pane, Application Insights is now visible
    • Link is shown under Monitoring > Application Insights
b. First-time Setup
    • Choose:
        ○ Collection Level: Recommended
        ○ Enable Profiler (optional)
        ○ Snapshot Debugger / SQL Monitoring (optional)
    • Click Apply, confirm restart of app

5. Exploring Application Insights Features
a. Application Map
    • Visual dependency map of app components
    • Shows number of calls, latency, and failures
    • Useful for tracing service dependencies and slow operations
b. Performance
    • View request duration, frequency, and response time trends
    • Breakdown by operation, dependency, or role
    • Compare durations and identify long-running requests
c. Live Metrics
    • Near real-time view of:
        ○ Incoming/outgoing requests
        ○ Response time
        ○ Server health
        ○ Memory usage
d. Availability
    • Track uptime using availability tests
    • Can create synthetic ping tests from global test agents
    • View results: % availability, failures, locations
e. Failures
    • Detect:
        ○ HTTP 4xx/5xx errors
        ○ Exception types
        ○ Failed dependencies (e.g., DB or API calls)

6. Additional Monitoring Options
a. Alerts
    • Navigate: Monitoring > Alerts
    • Create alert rules based on metrics like:
        ○ Server exceptions
        ○ Server response time
        ○ Failed request count
b. Metrics Blade
    • View custom metrics:
        ○ Page load time
        ○ Server response time
        ○ Dependency call duration
c. Application Dashboard
    • Auto-generated overview with tabs for:
        ○ Usage (users, sessions)
        ○ Reliability (failures, success rate)
        ○ Responsiveness (request duration)
        ○ Browser insights (user environment)

7. Best Practices for AZ-500
    • Use Application Insights for continuous monitoring of mission-critical apps.
    • Combine with Alerts + Action Groups to automate response.
    • Use Live Metrics and Snapshot Debugger for fast troubleshooting.
    • Integrate with Log Analytics for advanced querying (Kusto Query Language).
    • Ensure Monitoring is in place for all production workloads for both security and operational readiness.
 

## Managing Log Analytic Sources


1. Purpose of Log Analytics
    • Centralized querying and analysis platform for log and telemetry data.
    • Powered by Azure Monitor Logs, built on Kusto Query Language (KQL).
    • Supports security, performance, and compliance monitoring across services.

2. Log Analytics Workspace
    • Container where log data is collected and stored.
    • Resources send telemetry to a workspace.
    • You can connect:
        ○ Azure VMs
        ○ Azure PaaS resources
        ○ On-premises systems (via agents)
        ○ Diagnostics settings from other Azure services
Workspace Properties:
    • Name
    • Region (must match data sources in many cases)
    • Retention policy
    • Linked with Defender for Cloud, Sentinel, Monitor

3. Supported Data Sources
a. Azure Resources
    • VMs (via Azure Monitor Agent)
    • App Services
    • Key Vault
    • Storage Accounts
    • Network Security Groups (NSGs)
    • Azure Firewall
    • Application Gateway
    • Azure SQL
b. Custom Logs
    • Upload .log files or use custom-defined schema.
    • Parse with regular expressions or delimiters.
c. Agents
    • Azure Monitor Agent (AMA) – current standard.
    • Log Analytics Agent (MMA/OMS) – legacy, being deprecated.

4. Connect Data Sources to Workspace
a. Azure VM
    1. Go to Monitor > Virtual Machines
    2. Click Enable
    3. Select existing workspace or create one
    4. Uses Data Collection Rule (DCR) if using AMA
b. PaaS Services
    • Go to resource (e.g., Storage Account)
    • Navigate to Diagnostic Settings
    • Click Add diagnostic setting
    • Choose:
        ○ Log types (e.g., Read/Write/Delete requests)
        ○ Metrics
        ○ Destination: Log Analytics, Event Hub, Storage

5. Diagnostic Settings
    • Define what data is sent and where it goes
    • Up to 5 diagnostic settings per resource
    • Can send to:
        ○ Log Analytics
        ○ Event Hub
        ○ Storage Account
    🔐 For security, always log:
        ○ Admin operations
        ○ Authentication attempts
        ○ Network changes

6. Log Retention & Management
    • Default retention: 30 days
    • Can be configured per workspace
    • Older data incurs additional storage cost
    • Use Data Export rules to move logs to storage

7. Querying Logs with KQL
    • Go to Logs under the workspace or resource
    • Use tables like:
        ○ Heartbeat, Perf, SecurityEvent, AzureActivity, AppRequests
    • Sample query:
SecurityEvent
| where TimeGenerated > ago(1d)
| summarize count() by EventID

8. Best Practices (AZ-500 Relevant)
    • Use centralized Log Analytics workspace for visibility across tenants/subscriptions.
    • Configure diagnostic settings for all critical resources (Storage, NSGs, Key Vaults).
    • Use Data Collection Rules for granular control of what logs get sent.
    • Integrate with Microsoft Sentinel for threat hunting and incident response.
    • Enforce access control (RBAC) on workspaces to protect sensitive logs.
    • Enable retention policies and data export for compliance 
