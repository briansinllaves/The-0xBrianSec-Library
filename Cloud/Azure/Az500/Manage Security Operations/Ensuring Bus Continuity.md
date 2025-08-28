# Ensuring Business Continuity

## Azure Backup Solutions

### 1. Why Backups Matter

* Protect against data loss (deletion, corruption, ransomware).
* Ensure business continuity and regulatory compliance.
* Back up:

  * Data (files, VMs, DBs)
  * Service configurations (apps, networking, infra)

### 2. Key Concepts

* **RPO (Recovery Point Objective):** Max data loss allowed (e.g., “1 hour”).
* **RTO (Recovery Time Objective):** Max downtime allowed (e.g., “20 minutes”).
* RPO drives backup frequency; RTO drives restore speed.

### 3. Azure Backup Capabilities

* Azure VMs (snapshots)
* SQL Server on VMs
* Azure Files & Blobs
* On-prem workloads via **MARS** or **Azure Backup Server**
* Managed Disks, App Service configs
* Supports encryption, soft delete, retention policies, multi-region.

### 4. Backup vs HA vs DR

* **Backup:** Point-in-time copy.
* **HA:** Keeps service up.
* **DR:** Replicates full service elsewhere (Azure Site Recovery).

### 5. Backup Frequency

* RPO 1 hr → hourly backup.
* RPO 10 mins → use SQL log shipping/continuous.

### 6. Retention

* Short-term (daily/weekly) and long-term (monthly/yearly).
* Immutability for compliance (HIPAA, GDPR).

### 7. Storage Location

* Stored in **Recovery Services Vault** or **Backup Vault**.
* Storage options: LRS (cheap), GRS (cross-region).

### 8. Azure Site Recovery (ASR)

* DRaaS: replicates physical, VMware/Hyper-V, or Azure VMs.
* Supports failover and failback.

### 9. VM & Service Redundancy

* VM replication across regions.
* GRS storage for data.
* Deployment slots (App Service).
* DB replicas cross-region.

### 10. Load Balancing

* Distributes traffic, excludes unhealthy VMs, scales automatically.

### 11. Example Scenarios

| Service     | RPO | RTO | Notes         |
| ----------- | --- | --- | ------------- |
| E-commerce  | 5m  | 15m | Very critical |
| Docs server | 4h  | 6h  | Low priority  |
| Orders DB   | 10m | 30m | High-priority |

### 12. Best Practices

* Use vaults with **soft delete**.
* Encrypt with **CMK** if needed.
* Apply RBAC.
* Test restores.
* Set alerts for failures.
* Combine Backup + ASR.

---

## Enabling Virtual Machine Replication

### 1. Objective

* Enable **Azure Site Recovery** for cross-region VM protection.

### 2. Terminology

* ASR = Azure Site Recovery
* Primary = source region
* Secondary = replica region
* Failover = switch to replica
* Test Failover = non-prod test
* RPO = data loss allowed
* RTO = downtime allowed

### 3. Pre-reqs

* VM with managed disks.
* Supported region.
* Site Recovery extension auto-installed.

### 4. Enable Replication

1. VM → Disaster Recovery.
2. Basics → Target region.
3. Advanced → Replica RG, Replica VNet, Disk type.
4. Start replication.

### 5. Validate

* Status = Protected.
* Replication Health = Healthy.
* RPO few mins.
* Failover buttons active.

### 6. Test Failover

* Pick recovery point.
* Create test VM in replica VNet.
* Validate, then Cleanup.

### 7. Failover

* For outage or disaster.
* Select recovery point → Failover.
* Commit or failback.

### 8. Monitoring

* Check last test failover.
* Monitor agent health.

### 9. RG Management

* ASR creates **-asr** RG with replica disks, VNets.

### 10. Best Practices

* Use GRS disks.
* Test quarterly.
* Monitor RPO in portal/Log Analytics.
* Combine Backup + ASR.

### 11. Considerations

* Replication adds cost.
* Failover VMs may need rename/IP change.
* Not all VM SKUs supported.
* External deps (DNS, certs) not replicated.

---

## Backing Up Azure Virtual Machines

### 1. Purpose

* Protect Azure VMs with Recovery Services vault.

### 2. Recovery Services Vault

* Logical container for backup items, policies, ASR.

### 3. Backup Process

1. Create vault.
2. Configure workload = Azure VM.
3. Assign policy.
4. Add VMs.
5. Enable backup.

### 4. Policies

* Standard (daily) or Enhanced (multiple/day).
* Retention: daily, weekly, monthly, yearly.

### 5. Monitoring

* Vault > Backup items.
* VM > Backup (Ops).

### 6. Restore Options

* Restore VM → full new/original.
* File Recovery → mount recovery disk.

### 7. On-Prem

* Use **MARS** or **MABS**.

### 8. Security

* Encrypted at rest (CMK option).
* Soft delete enabled.
* RBAC controls.

### 9. Best Practices

* Enhanced policies for mission-critical.
* Test restores.
* Vault + VM in same region.

---

## Managing Azure SQL Backups

### 1. Overview

* SQL Database auto-backups enabled.
* Supports PITR + LTR.

### 2. Redundancy

* LRS, ZRS, or GRS (default).

### 3. Encryption

* **TDE** on by default.
* CMK possible.

### 4. PITR

* Default retention = 7 days (up to 35).

### 5. LTR

* Weekly/monthly/yearly backups up to 10 years.

### 6. Deleted DBs

* Can restore if within retention window.

### 7. Limitations

* No .bak access.
* Logical backups only.

### 8. SQL in VMs

* Use Recovery Services vault.

### 9. On-Prem SQL

* Requires MABS + vault credentials.

### 10. Security

* RBAC controls.
* Audit logs track backup config.

### 11. Best Practices

* Match redundancy to SLA.
* Enable LTR for compliance.
* Review PITR/LTR regularly.

---

## Restoring SQL Using the Portal

### 1. Importance

* Recovers from deletion, corruption, ransomware.

### 2. Entry

* Portal → SQL Databases → Select DB.

### 3. Backup Scope

* Managed at **SQL Server** level.

### 4. Restore Process

1. SQL Server → Data Mgmt → Backups.
2. Choose restore type: PITR or LTR.
3. Provide new DB name.
4. Review + Create.

### 5. Post-Restore

* Monitor progress in notifications.
* New DB appears in list.

### 6. Networking

* May need to enable firewall/public access.

### 7. Security

* RBAC, TDE, and audit logs apply.

### 8. Best Practices

* Test restores.
* Know PITR vs LTR.
* Review redundancy config.

---

## Enabling Storage Account Replication

### 1. Replication Concept

* Copies data to a secondary region.
* Asynchronous → writes commit locally first.

### 2. Redundancy Options

* **LRS:** local only.
* **ZRS:** across zones.
* **GRS:** geo-redundant, paired region.
* **GZRS:** combines ZRS + GRS.

### 3. Configure in Portal

* Storage Account > Redundancy > select option.

### 4. Failover

* Manual → Prepare for failover.
* Account becomes LRS in new primary.
* DNS endpoints unchanged.

---

## Backing Up Azure Web Applications

### 1. Purpose

* Back up App Service configs + content.

### 2. Default

* Hourly automatic full backup.

### 3. Deployment Slots

* Prod slot + optional staging/test.

### 4. Tiers

* Free/Basic → only prod slot.
* Standard/Premium → multiple slots.

### 5. Custom Backup

* Choose storage account + container.
* Set schedule + retention.
* Optionally include DB.

### 6. Backup Now

* Trigger on-demand backup.

### 7. Partial Backup

* `_backup.filter` file in Kudu console excludes paths.

### 8. Restore

* Restore to slot or new app.
* Optionally include DB.

---

## Backing Up Azure File Shares

### 1. Setup

* Storage Account > File Shares > create.
* Upload directories/files.

### 2. Snapshots

* Manual snapshots for point-in-time.

### 3. Enable Backup

* File Share > Backup > Recovery Services Vault.
* Choose policy (frequency + retention).

### 4. Run Backup

* Trigger from vault or storage account.

### 5. Restore

* Restore share → Original or Alternate location.
* Conflict handling: overwrite/skip.

---

## Managing Data Archiving and Rehydration

### 1. Blob Storage Tiers

* **Hot:** frequent.
* **Cool:** infrequent.
* **Archive:** rarely accessed (offline).

### 2. Manual Change

* Blob → Change Tier → select Hot/Cool/Archive.

### 3. Rehydration

* Change Archive → Cool/Hot.
* Priority: Standard or High.
* Status: *rehydrate pending*.

### 4. PowerShell

```powershell
$acc = Get-AzStorageAccount -Name "eastyhz1" -ResourceGroupName "App1"
Get-AzStorageContainer -Context $acc.Context -Name budgets | Get-AzStorageBlob
```

### 5. Lifecycle Management

* Automate tier moves or deletions based on age.

### 6. Summary

* Archive is cheapest but offline.
* Rehydration takes time.
* Lifecycle rules optimize cost and compliance.
