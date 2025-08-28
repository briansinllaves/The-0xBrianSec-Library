# Monitoring Az Services

## Working with Action Groups

### Purpose

* Define how Azure responds when an alert triggers.
* Reusable bundles used by Azure Monitor and Defender.
* Scenarios:

  * Security incidents (unauthorized access, resource abuse)
  * Performance degradation (high CPU)
  * Compliance violations (untagged resources, disabled firewalls)

---

### Key Components

**Notifications**

* Email, SMS, Push (Azure app), Voice

**Actions**

* Automation Runbook, Logic App, Azure Function
* Webhook/Secure Webhook
* ITSM (e.g., ServiceNow)
* Event Hub (SIEM/SOAR integration)

---

### Creating an Action Group

1. Azure Monitor → Alerts → Action Groups → Create
2. Basics: name, RG, region (global scope)
3. Notifications: add email/SMS/etc.
4. Actions: add automation if needed
5. Tags optional
6. Review + Create

---

### Using in Alert Rules

* Resource → Monitoring → Alerts → Create Alert Rule
* Define:

  * Scope
  * Condition (e.g., CPU > 80%)
  * Action Group
  * Alert Details (severity 0–4)
* Evaluation frequency: e.g., 1 min, lookback 5 min
* Examples:

  * VM CPU > 80%
  * Web App HTTP 5xx errors > 1
  * Firewall rule deleted

---

### Security & Compliance Integration

* Defender for Cloud sends alerts via action groups
* Logic Apps enable auto-response (e.g., isolate VM, disable account)

---

### Management Notes

* Action groups reusable across all resources
* Central management under Azure Monitor > Alerts > Action Groups
* Recommended naming: `SecOps-Notify`, `AutoRemediate-Critical`

---

### Exam Notes

* Action groups = global
* Multiple groups per alert rule allowed
* Secure webhooks use OAuth2
* Tags help classify but optional
* Integrates with Activity Logs and Log Analytics (KQL)

---

## Configuring Alert Notification

### Purpose

* Detect abnormal/risky conditions
* Notify/respond automatically
* Improve security + compliance visibility

---

### Steps

1. Portal → Monitor

   * Areas: Overview, Alerts, Metrics, Activity Log, Insights
2. Enable VM monitoring → Configure Insights (requires AMA, VM powered on)
3. Create Alert Rule:

   * Scope: resource (e.g., Linux1)
   * Condition: signal + threshold (CPU > 80%)
   * Evaluation: 1 min freq, 5 min lookback
   * Action groups: select existing or new
   * Details: name + severity
   * Tags optional
   * Review + Create

---

### Post-Creation

* Edit alert: adjust thresholds, conditions, or action groups

### Additional Alerts

* Example: Network In Total > 500 MB

---

### Example Action Group (EmailAdmins)

1. Monitor > Alerts > Action Groups > Create
2. Basics: name, RG
3. Notifications: Email
4. Optional actions: Runbook, Logic App, Function, Webhook
5. Enable Common Alert Schema
6. Review + Create

---

### Notification Methods

* Email: confirmation + alert details
* SMS: short summary
* Azure app: push notification
* Voice: robocall

---

### Best Practices

* Use descriptive names (`Linux1CPUThreshold`)
* Group by severity to match SLA
* Use tags for cost tracking + filtering
* Enable Common Alert Schema
* Integrate with Log Analytics, Event Hub, Logic Apps, ITSM

---

## Enabling Web App Application Insights

### Purpose

* Deep app monitoring: performance, availability, usage
* Detect failures and bottlenecks
* Works best with .NET, Node.js, Java

---

### Deploy with Insights

* App Services → Create
* Configure basics: name, stack, region
* Monitoring: enable Application Insights (use existing or create new)

---

### Post-Deployment

* App → Monitoring → Application Insights
* Configure collection level, Profiler, Snapshot Debugger, SQL Monitoring

---

### Features

* **App Map**: visualize dependencies
* **Performance**: request duration, frequency
* **Live Metrics**: near real-time server health
* **Availability**: synthetic ping tests
* **Failures**: HTTP 4xx/5xx, dependency failures

---

### Alerts & Metrics

* Monitoring → Alerts: set rules (response time, failures)
* Metrics: page load time, response duration
* Auto dashboards: usage, reliability, responsiveness

---

### Best Practices

* Always enable for production workloads
* Combine with alerts + action groups
* Use Live Metrics for troubleshooting
* Integrate with Log Analytics (KQL)

---

## Managing Log Analytic Sources

### Purpose

* Centralized telemetry + log query platform
* Backed by KQL
* Supports monitoring for security, performance, compliance

---

### Workspace

* Container for logs + telemetry
* Linked with Defender for Cloud, Sentinel, Monitor
* Properties: name, region, retention

---

### Data Sources

* Azure resources: VMs, App Services, Key Vault, Storage, NSGs, Firewall, SQL
* Custom logs (.log files)
* Agents: AMA (current), MMA (legacy)

---

### Connect Resources

* VMs → Monitor → Virtual Machines → Enable → select workspace
* PaaS → Resource → Diagnostic Settings → add → send to Log Analytics/Event Hub/Storage

---

### Diagnostic Settings

* Define data type + destination (up to 5 per resource)
* Always log: admin ops, auth attempts, network changes

---

### Retention & Export

* Default retention: 30 days
* Configurable
* Data export rules for long-term storage

---

### KQL Query Example

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| summarize count() by EventID
```

---

### Best Practices

* Centralized workspace per org
* Configure diagnostics for all critical resources
* Use DCR for granular control
* Integrate with Sentinel for threat hunting
* Protect workspace with RBAC
* Use retention + export for compliance
