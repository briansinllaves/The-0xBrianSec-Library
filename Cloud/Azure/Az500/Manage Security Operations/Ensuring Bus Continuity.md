# Ensuring Bus Continuity

## Azure Backup Solutions 


1. Why Backups Matter
    • Protection against data loss (accidental deletion, corruption, ransomware).
    • Ensure business continuity and meet regulatory compliance.
    • Back up:
        ○ Data (files, VMs, DBs)
        ○ Service configurations (e.g., app settings, network config)

2. Key Concepts
Term	Meaning
RPO (Recovery Point Objective)	Max data loss allowed (e.g., “1 hour of orders”)
RTO (Recovery Time Objective)	Max downtime allowed (e.g., “service must recover within 20 minutes”)
    🔁 RPO drives backup frequency, RTO drives restore speed

3. Azure Backup Capabilities
Azure Backup supports:
    • Azure VMs (entire VM snapshots)
    • SQL Server on Azure VMs
    • Azure Files and Azure Blobs
    • On-premises machines via MARS or Azure Backup Server
    • Azure Managed Disks
    • App service configuration backups (e.g., Web App settings)
    ✅ Supports encryption, soft delete, multi-region storage, and retention policies

4. High Availability vs Backup
Feature	Purpose
Backup	Point-in-time copy of data for recovery
High Availability (HA)	Ensures uptime and data accessibility
Disaster Recovery (DR)	Enables full service replication to alternate location (e.g., Azure Site Recovery)

5. Backup Frequency Planning
    • Depends on RPO:
        ○ RPO = 1 hour → back up hourly
        ○ RPO = 10 minutes → use continuous backup (e.g., SQL Transaction Logs)
    • Not one RPO/RTO per org — they vary per workload

6. Retention Planning
    • Set short-term (daily, weekly) and long-term (monthly, yearly) retention
    • Meets compliance requirements (HIPAA, GDPR, etc.)
    • Immutable backup options protect against tampering

7. Storage Location & Compliance
    • Backups stored in:
        ○ Azure Recovery Services Vault
        ○ Azure Backup Vault (modern, RBAC-enabled)
    • Choose:
        ○ Locally Redundant Storage (LRS) – cost-effective
        ○ Geo-Redundant Storage (GRS) – for DR across regions
    🌐 Data residency matters for compliance: choose regions wisely

8. Azure Site Recovery (ASR)
    • Disaster Recovery as a Service (DRaaS)
    • Replicates:
        ○ On-prem physical servers
        ○ VMs (Azure or on-prem)
        ○ VMWare/Hyper-V workloads
    • Supports failover and failback for business continuity

9. VM & Service Redundancy
    • VM replication across regions
    • Use Geo-redundant Storage (GRS) for data
    • Use App Service Deployment Slots for zero-downtime updates
    • Use read-only DB replicas for cross-region failover/performance

10. Load Balancing & Fault Tolerance
    • Distribute traffic across multiple backend VMs
    • Auto-detects and excludes unhealthy VMs
    • Supports scalability and resilience

11. Example Scenarios
Service	RPO	RTO	Notes
E-commerce payment	5 mins	15 mins	Very critical
Internal documentation server	4 hrs	6 hrs	Low urgency
Customer orders DB	10 mins	30 mins	High-priority

12. Best Practices (AZ-500 Relevant)
    • Use Recovery Services Vaults with locked soft delete
    • Encrypt backups with customer-managed keys (CMK) if needed
    • Set role-based access control (RBAC) on vaults
    • Test restore operations regularly
    • Configure alerts for backup failures
    • Combine Azure Backup and ASR for full protection

## Enabling Virtual Machine Replication




1. Objective
    • Enable Disaster Recovery for Azure VMs using Azure Site Recovery (ASR).
    • Replicate VM disks and configurations to a secondary Azure region.
    • Provides business continuity in case of region-wide failure or planned failover.

2. Terminology
Term	Description
ASR (Azure Site Recovery)	Azure’s Disaster Recovery as a Service (DRaaS)
Primary Region	Source region where original VM resides
Secondary Region	Target region for replica deployment
Replication Health	Indicates sync status and issues
Failover	Switch operations from primary VM to secondary replica
Test Failover	Simulate failover without impacting production
Cleanup Test Failover	Removes test VM and validates failover process
RPO (Recovery Point Objective)	Max tolerable data loss, shown in minutes
RTO (Recovery Time Objective)	Max tolerable downtime, used in planning

3. Pre-requisites
    • A running Azure VM in a supported region.
    • Azure VM must use managed disks.
    • Disaster Recovery must be enabled via the Azure portal or Azure CLI.
    • VM should have Site Recovery extension installed (automatically handled).

4. Enabling Replication
a. Portal Navigation:
    1. Go to Virtual Machines > [VM Name]
    2. Click Disaster Recovery under Operations
b. Basics Tab:
    • Set Disaster Recovery between zones to No (for cross-region failover)
    • Select Target Region (e.g., West Central US)
c. Advanced Settings Tab:
    • Default:
        ○ Replica Resource Group: [source-name]-asr
        ○ Replica VNet: auto-created in target region
    • Disk Type: Match source (e.g., Premium SSD)
    • Cache storage & churn threshold are customizable
d. Review + Start Replication:
    • Start the process
    • Azure provisions:
        ○ Replica disk(s)
        ○ Replica network
        ○ Recovery Services resources

5. Post-Replication Validation
After deployment completes:
    • Navigate to Disaster Recovery for the VM
    • Verify:
        ○ Replication Health = Healthy
        ○ Status = Protected
        ○ RPO = ~ few minutes
        ○ Agent = Healthy
    • Failover and Test Failover buttons will become active after full sync.

6. Test Failover Process
    1. Click Test Failover
    2. Select Recovery Point (latest or previous snapshot)
    3. Choose Replica VNet
    4. Azure creates and boots a temporary VM in the secondary region
    5. Use it to validate disaster recovery plan
    6. Click Cleanup Test Failover after confirmation

7. Failover Operation
    • Used during:
        ○ Regional outages
        ○ Disaster recovery scenarios
        ○ Unrecoverable service disruption
Steps:
    1. Click Failover
    2. Select Recovery Point
    3. Initiate failover → ASR boots replica VM in target region
    4. Optionally commit failover (make permanent) or fail back

8. Failover Readiness Monitoring
    • Check Last successful test failover
    • Agent version & status must be current
    • Address any configuration issues shown in portal

9. Azure Resource Group Management
    • ASR creates a new resource group (e.g., app1-asr)
    • Contains:
        ○ Replica disks
        ○ Replica VNet
        ○ Supporting infra for DR

10. Best Practices (AZ-500 Focus)
    • Use Geo-redundant storage on VM disks when possible
    • Perform Test Failover at least quarterly
    • Monitor RPO metrics via portal or Log Analytics
    • Combine ASR with Azure Backup for full protection
    • Protect all mission-critical VMs in production
    • Document DR plans and perform periodic drills
    • Enable Alerts for replication health or failures

11. Key Considerations
    • Replication incurs additional cost (compute/storage/network)
    • Failover VMs can be renamed or re-IP’ed post-failover
    • Not all VM SKUs are supported in all regions — check region pairing
    • ASR doesn’t replicate:
        ○ External dependencies (e.g., DNS config)
        ○ Certificates stored outside the VM
 
## Backing Up Azure Virtual Machines


1. Purpose
    • Use Azure's cloud-native backup service to protect Azure VMs.
    • Supports VM-level, disk-level, and file-level restores.
    • Backup configurations are managed via a Recovery Services vault.

2. Core Component: Recovery Services Vault
    • Logical container to manage:
        ○ Backup items
        ○ Policies
        ○ Replicated VMs (ASR)
    • Deployed per-region, associated with subscriptions.

3. Backup Process Overview
    1. Create or use existing Recovery Services vault.
    2. Configure backup source: e.g., Azure VM.
    3. Assign or create backup policy (schedule + retention).
    4. Select target VM.
    5. Enable backup.
    6. Monitor backup and trigger on-demand backup if needed.

4. Initiating Backup (Step-by-Step)
a. Go to:
Azure Portal > Recovery Services vaults > [Vault Name] > Backup
b. Select:
    • Where is your workload running? → Azure
    • What do you want to back up? → Virtual machine
c. Configure Backup:
    • Choose:
        ○ Policy Type: Standard (1x/day) or Enhanced (multiple/day)
        ○ Use DefaultPolicy or create a custom policy
d. Add VMs:
    • VMs must be in the same region as the vault
    • Can optionally exclude data disks
e. Click Enable Backup

5. Backup Policies
    • Set:
        ○ Frequency: Daily or Weekly
        ○ Time: When to run backup
        ○ Retention: Daily, Weekly, Monthly, Yearly
        ○ Instant Recovery Snapshots (for quick restores)
    💡 Custom policies offer more flexibility for RPO/RTO alignment

6. Monitoring & Validation
    • Navigate to:
        ○ Vault > Backup items
        ○ View:
            § Backup item count
            § Pre-check status
            § Last backup status
    • Or:
        ○ VM > Backup (under Operations)

7. Initial Backup
    • Until the first backup completes, restore actions are disabled.
    • You can click Backup Now to trigger manually.
    • Default retention: 1 month (customizable).

8. Restore Options
    • Restore VM:
        ○ Restores entire VM to a new VM or original location
    • File Recovery:
        ○ Mounts recovery disk temporarily to extract specific files
    🛡 Restore points are created daily or per policy.

9. On-Premises Workloads
    • Recovery Services vault also supports:
        ○ Windows/Linux file servers
        ○ Hyper-V/VMware
        ○ SQL Server, SharePoint, Exchange
    • Requires Microsoft Azure Recovery Services Agent (MARS)
    • Download:
        ○ Agent software
        ○ Vault credentials (for authentication)

10. Security & Governance (AZ-500 Specific)
    • Backup data is:
        ○ Encrypted at rest
        ○ Can use Customer-Managed Keys (CMK)
    • Soft delete protects against accidental deletions
    • RBAC enforces access control for backup management
    • Alerts/logs can be integrated into Azure Monitor or Sentinel

11. Best Practices
    • Use enhanced policies for mission-critical VMs
    • Regularly test Restore VM and File Recovery
    • Keep vault and VM in same region
    • Use tags for tracking backup scope
    • Audit using:
        ○ Azure Activity Logs
        ○ Backup reports in Log Analytics

 ## Managing Azure SQL Backups


1. Overview
    • Azure SQL Database provides automatic backups by default.
    • Supports:
        ○ Point-in-Time Restore (PITR)
        ○ Long-Term Retention (LTR)
    • Backup configuration is managed at the SQL server level, not the database level.

2. Backup Redundancy Settings
    • Configure during database creation or after.
    • Navigate to:
SQL Database > Settings > Compute + Storage > Backup Storage Redundancy
Options:
        ○ Locally Redundant Storage (LRS)
        ○ Zone Redundant Storage (ZRS)
        ○ Geo Redundant Storage (GRS) (default)
    GRS enables backups to be replicated to a paired region for disaster recovery.

3. Encryption
    • Transparent Data Encryption (TDE) is ON by default:
        ○ Encrypts data files, logs, and backups
        ○ Can use Microsoft-managed or customer-managed keys (CMK)

4. Accessing Backup Settings
    • Open SQL Server, not just the Database
    • Go to:
SQL Server > Data Management > Backups

5. Point-in-Time Restore (PITR)
    • Enabled by default.
    • Default retention: 7 days
    • Adjustable up to 35 days
    • Navigate to:
Backups > Retention Policies > Configure Policies
    PITR helps meet short-term recovery goals (low RPOs).

6. Differential Backups
    • Default frequency: every 12 hours
    • Changeable up to every 24 hours
    • Tracks changes since last full backup (optimized storage & performance)

7. Long-Term Retention (LTR)
    • Separate policy from PITR
    • Store weekly/monthly/yearly backups for up to 10 years
    • Use when:
        ○ Compliance requires long-term backup retention (e.g., HIPAA, GDPR)
Configure in:
SQL Server > Backups > Retention Policies > Configure Policies

8. Deleted Databases
    • Navigate to:
SQL Server > Data Management > Deleted Databases
    • You can restore recently deleted databases if within retention window.

9. Manual Backup Not Needed
    • Azure SQL Database handles all backup scheduling, storage, encryption.
    • Admins only configure policies—not perform actual backups.

10. Backup Limitations
    • Only logical backups—no direct access to *.bak files
    • Not suitable for native SQL Server restore workflows
    • Can't use Recovery Services Vault for managed Azure SQL Database

11. Recovery Services Vault: For Azure SQL in IaaS (VMs)
    • Navigate to:
Recovery Services Vault > Backup > Azure > SQL Server in Azure VM
    • Requires:
        ○ Agent installed on VM
        ○ Vault credentials for auth
        ○ Manual configuration of backup policies

12. On-Prem SQL Server Backups
    • Select:
        ○ Where is workload running? → On-Premises
        ○ What do you want to back up? → Microsoft SQL Server
Steps:
    1. Install Azure Backup Server (MABS)
    2. Download vault credentials
    3. Configure backup on-prem via MABS UI

13. Security & Compliance (AZ-500 Relevance)
    • Role-based Access Control (RBAC) manages backup config access.
    • Audit logs track backup configuration changes.
    • LTR aligns with data retention compliance frameworks.
    • Encryption via TDE with optional CMK from Azure Key Vault.
    • Use Azure Monitor or Log Analytics for alerts/metrics.

14. Best Practices
    • Choose redundancy based on SLA and DR requirements
    • Match backup frequency to RPO/RTO goals
    • Enable LTR for compliance
    • Use CMK + TDE if customer control is needed
    • Regularly review:
        ○ PITR/LTR retention
        ○ Deleted DBs window
        ○ SQL Server security settings
 
## Restoring SQL Using the Portal 


1. Importance of Restore
    • Ensures business continuity by recovering from:
        ○ Accidental deletion
        ○ Data corruption
        ○ Malware or ransomware
    • Built-in Azure SQL Database backups support point-in-time restore (PITR) and long-term retention (LTR)

2. Entry Point
    • Go to Azure Portal > SQL Databases
    • Select the SQL database you want to restore

3. Understand Backup Scope
    • Backups are configured and managed at the SQL Server level, not the individual database level
    • In the database blade, options like Compute + storage show the storage redundancy level but not full backup management

4. Backup Redundancy Configuration
    • Navigate to: SQL Database > Settings > Compute + Storage
    • Backup storage redundancy options:
        ○ Locally-redundant (LRS)
        ○ Zone-redundant (ZRS)
        ○ Geo-redundant (GRS) (Default)
    • GRS replicates backup blobs to a paired Azure region

5. Geo-Replication vs Backup
    • Geo-replica: Real-time sync replica for HA/disaster recovery
        ○ Access via Replicas blade
        ○ Use "Create replica" for regional failover
    • Backups: Point-in-time snapshots for true recovery
        ○ Available even if the primary DB is deleted

6. Navigate to Server-Level Backup
    • In database Overview blade: click Server name link
    • Under SQL Server > Data Management > Backups:
        ○ Tab: Available backups
        ○ Toggle: Active / Deleted Databases
        ○ Action column: Click Restore

7. Restore Process
    • Restore type: Choose between:
        ○ Point-in-time restore (PITR): Select timestamp
        ○ Long-term retention (LTR): Restore from weekly/monthly/yearly backups (if configured)
    • Restore wizard fields:
        ○ New database name auto-generated with date-time suffix
        ○ Server, Elastic Pool, Compute + Storage, Backup redundancy options
        ○ Click Review + Create, then Create

8. Post-Restore Steps
    • Monitor: Notification bell shows deployment progress
    • New DB appears in SQL Databases list
    • It’s a fully separate database instance

9. Query the Restored DB
    • Use Query Editor (Preview)
        ○ Login using SQL Authentication or AAD
        ○ Error: "Public network access disabled" if networking isn’t configured
Fix:
    • Navigate to: SQL Server > Security > Networking
        ○ Enable Public access or
        ○ Add client IP / VNet firewall rule
    • Retry Query Editor to validate access
        ○ Example: Expand Tables, run SELECT TOP 1000 * FROM Customers

10. Security Considerations
    • Backup/restore process inherits:
        ○ RBAC permissions
        ○ TDE encryption (Transparent Data Encryption is ON by default)
    • Ensure firewall/network settings align with restored environment
    • Use Azure Monitor and Log Analytics to audit access and activity

11. Summary
    • Restoring SQL via Azure Portal is straightforward but managed at the server level
    • Supports compliance and operational recovery needs
    • Test your backup & restore process regularly to meet RPO/RTO requirements
    • Reinforce with retention policies, firewalls, and key vault encryption

AZ-500 Tips:
    • Know where SQL backups are configured (Server > Data Management)
    • Understand PITR vs LTR options
    • Backup storage redundancy settings
    • Networking/firewall requirements for restored DB access
    • Role of TDE, RBAC, and Azure Backup Server for SQL in VMs/on-prem

##  Enabling Storage Account Replication


I. Topic Overview
    • Title: Enabling Storage Account Replication
    • Presenter: Dan Lachance
    • Purpose: Achieve high availability for Azure storage accounts using replication

II. Replication Concept in Azure
    • Replication = Copying data to a secondary region
    • Known as geo-redundancy or geo-replication
    • Azure uses asynchronous replication:
        ○ Write completes on primary first
        ○ Then syncs to secondary (not simultaneous)

III. Navigating to Storage Accounts in Portal
    • Azure Portal → Storage accounts
    • View includes:
        ○ Recent and Favorite tabs
        ○ Columns: Name, Type, Last Viewed

IV. Creating a New Storage Account with Replication
A. Click "Create" on Storage Accounts page
B. Configure Basics
    • Storage account name
    • Region
    • Performance tier
    • Redundancy (default: GRS)
C. Redundancy Dropdown Options
    • LRS: Local only, cheapest, no regional protection
    • ZRS: Across zones, protects against datacenter failures
    • GRS: Geo-redundant, secondary region added
    • GZRS: Combines ZRS and GRS for max durability
D. Default: GRS with Read Access
    • Checkbox auto-enabled for read-access in case of regional unavailability
E. Cancel Creation for Demo Purposes
    • Presenter instead opens existing storage account eastyhz1

V. Enabling Replication on Existing Storage Account
A. Open eastyhz1 → Data Management → Redundancy
B. Current Setup
    • Set to LRS
    • Map shows Primary: East US
    • No secondary region assigned
C. Change to GRS
    • Select from dropdown
    • Secondary region auto-assigned (e.g., West US)
    • Click Save
D. Post-Configuration
    • Secondary (West US) appears as Available
    • Initial sync in progress
    • Duration depends on account contents (blobs, tables, queues, files)

VI. Prepare and Perform Failover
A. After Sync Completion
    • Button "Prepare for failover" becomes available
B. Click "Prepare for failover"
    • Warnings shown:
        1. Last sync time – possible data loss
        2. After failover, account becomes LRS
        3. You can reconfigure to GRS again later
C. Confirm Failover
    • Type yes → Click Failover
D. Failover Progress
    • East US = Primary
    • West US = Secondary
    • Now in progress → West US becomes new primary

VII. Post-Failover Behavior
A. Redundancy View Changes
    • Only one location now shown (West US as LRS)
    • Geo-replication removed after failover
B. DNS/Endpoint Behavior
    • No changes for apps/users
    • DNS (FQDN) remains same (e.g., eastyhz1.blob.core.windows.net)
    • Now points to the new primary (West US)
C. View Endpoints in Settings
    • Endpoints show same names
    • Reference the new primary region

VIII. Conclusion
    • Replication is asynchronous
    • Failover:
        ○ Temporary conversion to LRS
        ○ Must manually re-enable GRS/GZRS if needed
    • No endpoint reconfiguration required
    • Supports disaster recovery and high availability in Azure
 
## Backing Up Azure Web Applications


I. Introduction
    • Purpose: Enable data availability by backing up Azure Web Apps (App Services)
    • Some apps contain static content (e.g., PDFs) that rarely change
    • Covers automatic vs custom backups, partial backups, deployment slots, and restore options

II. Accessing App Service in Azure Portal
    • Navigate to App Services
    • Select running app (e.g., samplenewandwonderfulapp)
    • View app properties and settings (Region, Status, Resource Group, App Service Plan)

III. Default Backup Behavior
    • Automatic backup every 1 hour
    • Requires no manual storage account config
    • No partial backup support in default mode
    • Backup page shows:
        ○ List of backups
        ○ Status (Succeeded/Failed)
        ○ Type (Automatic)
        ○ Restore link (to current or other deployment slots)

IV. Deployment Slots
    • Found under "Deployment" in app settings
    • Default slot: Production
    • Optional: Add more slots (e.g., staging/testing)
    • Slot usage during restore:
        ○ Restore to non-production slot to avoid downtime

V. App Service Tier Impacts Backup
    • Go to Scale up (App Service plan) to check pricing tier
    • Example: Standard S1
        ○ Basic/Free tiers: only production slot backup/restore allowed
        ○ Standard/Premium tiers: support multiple slots for backup/restore

VI. Configure Custom Backups
    • Go to Backups → Click Configure custom backups
    • Custom backup steps:
        1. Select Storage account
        2. Create or choose Blob container (e.g., webappbackup)
        3. Set schedule:
            § Example: Every 1 Day (can be hourly)
            § Define start time, time zone
        4. Set retention:
            § Default: 30 days
            § 0 = indefinite (increases cost)
            § Optional: "Keep at least one backup at all times"
        5. Click Next: Advanced
            § If linked DB exists, option to back it up appears
            § If no DBs, table is empty
        6. Click Configure

VII. Backup Now Option
    • Once custom backup is configured:
        ○ "Backup Now" button is enabled
        ○ Click to trigger on-demand backup
        ○ Shows Status: In Progress
        ○ After completion, shows Status: Succeeded

VIII. Creating a Partial Backup
    • Use Kudu Debug Console:
https://<appname>.scm.azurewebsites.net/DebugConsole
    • Navigate to: site/wwwroot/
    • Create a file: _backup.filter
    • Inside file: list of files/folders to exclude (e.g., docs/, static/)
    • Upload via drag-and-drop in console or FTP

IX. Restoring from Backup
    • Click Restore for desired backup
    • Source options:
        ○ Automatic backup
        ○ Custom backup
        ○ Storage (external Blob backup)
    • Destination options:
        ○ Existing deployment slot
        ○ Create new app
    • Advanced options:
        ○ Ignore conflicting domain names
        ○ Include database
    • Click Restore → monitor via Notification bell

X. Key Points Summary
    • Default: hourly full backup; no config needed
    • Custom backups allow scheduling, filtering, retention
    • Only supported in Standard tier and above
    • _backup.filter enables partial backups
    • Restore supports production or staging slots, or new apps
    • DB backup and restore optional in advanced settings
 
## Backing Up Azure Files Shares


I. Introduction
    • Purpose: Demonstrate how to back up an Azure Files shared folder
    • Covers:
        ○ Creating file shares
        ○ Uploading content
        ○ Enabling snapshots
        ○ Enabling backup via Recovery Services Vault
        ○ Triggering and restoring backups

II. Initial Setup: Access Storage Account
A. Navigate to Storage Account
    • Azure Portal → Storage accounts
    • Select an existing storage account (e.g., eastyhz1)
B. Go to File Shares
    • Left pane → Data Storage → File shares
    • View existing shares or create a new one

III. Create and Populate a File Share
A. Create New File Share
    • Click + File Share
    • Name: e.g., projects
    • Click Create
B. Add Directory and Files
    • Open file share → Click Add Directory (e.g., current_year)
    • Click Browse → Click Upload to upload files
C. Optional: Connect Locally
    • Click Connect (top of the page)
    • Instructions for Windows (map drive letter), Linux, macOS
    • Can be used by local backup software

IV. Create Snapshot (Point-in-Time Copy)
A. Snapshots for Manual Protection
    • Left pane → Operations → Snapshots
    • Click Add Snapshot (name: snapshot1)
    • Snapshot can be browsed or mounted via SMB

V. Configure Azure Backup for File Share
A. Go to Backup
    • Left pane under Operations → Click Backup
B. Select/Create Recovery Services Vault
    • Choose existing or create new vault
    • Assign to a Resource Group
C. Choose or Edit Backup Policy
    • Default: Daily at 7:30 PM, 30 days retention
    • Optional changes:
        ○ Hourly/Daily frequency
        ○ Retain daily, weekly, monthly, yearly points
        ○ Timezone and retention sliders
D. Storage Account Lock
    • Enabled by default to prevent accidental deletion of the storage account during backup
E. Click Enable Backup
    • Triggers deployment (ConfigureProtection)

VI. Verify and Run Initial Backup
A. Access Recovery Services Vault
    • Go to Backup items under Protected items
    • Find Azure Storage (Azure Files)
B. Initial Status
    • File share (e.g., projects) shows as pending
    • Click the ellipsis (three dots) → Select Backup now
C. Confirm Backup
    • Retain setting defaulted
    • Click OK
    • After completion, status shows Success with timestamp
D. Alternative View in File Share
    • Back in storage account → File shares → projects → Backup tab
    • View:
        ○ Recovery vault
        ○ Last backup status
        ○ Jobs in the last 24 hours

VII. Monitor Backup Jobs
    • View Backup Jobs page
    • See status and history of operations

VIII. Restore File Share
A. Initiate Restore
    • In Recovery Vault → Backup Items → Click ellipsis → Restore Share
B. Choose Restore Point
    • Pick a backup point (once completed)
C. Restore Destination Options
    1. Original Location
        ○ Conflict handling: Overwrite or Skip
    2. Alternate Location
        ○ Choose:
            § Storage account
            § File share
            § Folder path
            § Conflict handling
D. Click Restore
    • Monitored in Notification Bell

IX. Key Points Summary
    • Backing up Azure Files requires:
        ○ File Share in Storage Account
        ○ Recovery Services Vault
        ○ Backup policy
    • Snapshots offer manual protection
    • Backup jobs and restore options are visible in both storage account and vault
    • Restore supports overwrite, skip, or restore to alternate folder or storage account

## Managing Data Archiving and Rehydration


I. Introduction
    • Why archive? Legal, regulatory, or contractual reasons may require data retention even if not accessed frequently.
    • Blob storage tiers support cost-optimized retention:
        ○ Hot: Frequently accessed
        ○ Cool: Infrequently accessed
        ○ Archive: Rarely accessed, cheapest, offline until rehydrated

II. Accessing Blob Containers in the Portal
A. Navigate to Storage Accounts → Open storage account (e.g., eastyhz1)
B. Go to Containers under Data Storage
C. Open a container (e.g., budgets)
    • Files listed with info like Name, Modified, Access tier, etc.

III. Manually Changing Blob Access Tier
A. Change Tier Button Behavior
    • Grayed out if:
        ○ No file selected
        ○ Multiple blobs selected
    • Available when one blob is selected
B. Change Tier Flow
    • Select blob → Click Change tier
    • Choose from:
        ○ Hot (default)
        ○ Cool
        ○ Archive ← chosen in demo
    • Warning: Archive makes blob inaccessible until rehydrated
    • Cost impact if rehydrated before 180 days
C. Result
    • Blob marked Archive
    • Appears as a stub (unavailable for download/edit)

IV. Using PowerShell (Cloud Shell) to View Blob Tiers
A. Commands Used:
$acc = Get-AzStorageAccount -Name "eastyhz1" -ResourceGroupName "App1"
Get-AzStorageContainer -Context $acc.Context -Name budgets | Get-AzStorageBlob
    • Displays blobs and current access tiers (e.g., Archive)

V. Rehydrating an Archived Blob
A. Open blob → Click Change tier
B. Select new tier:
    • Hot or Cool (Cool used in demo)
    • Choose Rehydrate Priority:
        ○ Standard (default)
        ○ High (faster but more expensive, for emergencies)
C. Click Save
    • Status: Rehydrate Pending
    • Archive status updates once complete
    • Access tier changes to Cool (or Hot)

VI. Post-Rehydration Behavior
    • Blob becomes accessible again
    • Buttons like Download reappear
    • Tier can be changed again as needed

VII. Automating Tier Changes with Lifecycle Management
A. Navigate to storage account → Data management → Lifecycle management
B. Click Add a rule
C. Rule Options:
    • Scope: All blobs or filtered subset
    • Conditions:
        ○ If blob was last modified or created > X days ago
    • Actions:
        ○ Move to Cool
        ○ Move to Archive
        ○ Delete blob
        ○ Option: Skip blobs rehydrated in last 7 days
D. Use case:
    • Example: Archive blobs not modified in the last 90 days

VIII. Key Points Summary
    • Hot/Cool/Archive tiers support storage cost optimization
    • Archive is offline; requires rehydration
    • Manual and automated tiering (via lifecycle rules) supported
    • Rehydration may take minutes to hours
    • PowerShell can be used for tier inspection
    • Lifecycle rules allow automated archival/deletion based on age or access

