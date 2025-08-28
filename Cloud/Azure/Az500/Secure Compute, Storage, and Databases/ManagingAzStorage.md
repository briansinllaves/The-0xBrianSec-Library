# Managing Azure Storage

## Enabling Storage Account Blob File Versioning

### Configuration Process

**Navigation:** `Storage Account → Container → Data Protection → Tracking → "Enable versioning for blobs"`

**Versioning Behavior:**
- Creates new version when blob is modified
- Previous versions persist when blob is deleted
- Enables point-in-time recovery
- Helps with accidental modifications or deletions

---

## Managing Blob Soft Deletion

### Configuration Settings

**Navigation:** `Storage Account → Container → Data Protection → Recovery`

**Configuration Options:**
- **Enable soft deletion for blobs** - Protects against accidental deletion
- **Retention period** - Default is 7 days before permanent purge
- **Enable soft delete containers** - Protects entire containers

**Recovery Process:**
- Soft deleted items remain accessible during retention period
- Can be restored before purge deadline
- Provides protection against accidental or malicious deletion

---

## Working with Immutable Blob Storage

### Purpose and Use Cases

**Immutable Storage:**
- Blob storage that cannot be modified or deleted
- Compliance and regulatory requirements
- Legal hold scenarios
- Audit trail preservation

### Setup Process

**Initial Configuration:**
1. Create storage account with **local redundancy**
2. **Data Protection** → Enable "Enable version-level immutability support"
3. Navigate to `Storage Account → Container → Overview → Data Protection → Access Control → Manage Policy`

### Immutability Policies

**Time-Based Retention:**
- Set retention period during which blobs cannot be modified or deleted
- Can have different time-based retention for different blobs
- **Warning:** If you lock time-based retention, you must wait before modification/deletion of blob or container

**Legal Hold:**
- Applied to individual blobs
- Cannot delete blob or file while legal hold is active
- Good for preserving storage evidence
- Independent of time-based retention

**Protected Writes:**
- Allow protective writes to append blocks
- Useful for log files where you continuously write/append data
- Maintains immutability while allowing data growth

---

## Managing Azure Storage Account Network Access

### Network Access Configuration

**Navigation:** `Storage Accounts → Container → Networking → Firewalls and VNets`

### Access Options

**Enable from all networks (Default):**
- Includes internet access
- **Warning:** Storage accounts are by default open to any network including the internet

**Enable from selected VNets and IPs:**
- Restricted network access
- Specify allowed virtual networks
- Define allowed IP address ranges

### Deployment Considerations

**Planning Questions:**
- How will the storage accounts be used?
- What other services need access?
- Where will you deploy VMs running code that needs storage account access?

### Access Methods

**Storage Account Access Keys:**
- 2 access keys per storage account
- Provide access to entire storage account
- Full administrative access

**Shared Access Signatures (SAS):**
- Restricted access to subset of storage account items
- Time-limited access
- Can be scoped to specific resources

---

## SAS Token Configuration

### SAS Token Properties

**Resource Types:**
- Service level access
- Container level access
- Object level access

**Allowed Permissions:**
- **r** - Read
- **w** - Write
- **d** - Delete
- **l** - List
- **a** - Add
- **c** - Create
- **u** - Update
- **p** - Process
- Immutable storage permissions
- Permanent delete permissions

**Access Controls:**
- Start and expiry time
- Allowed IP addresses
- Can be pointed to specific blob

---

## Enabling Storage Account Lifecycle Management

### Purpose

- Automatically remove items from storage account after specified time
- Security benefit: prevents sensitive data from lingering
- Cost optimization through tier transitions

### Manual Tier Management

**Navigation:** `Blob Container → Right-click blob → Change tier`

**Available Tiers:**
- **Hot** - Frequently accessed data
- **Cold** - Less frequently accessed data  
- **Archive** - Long-term storage, requires rehydration for access

### Automated Lifecycle Rules

**Configuration:** `Storage Account → Properties → Data Management → Lifecycle Management`

**Rule Configuration:**
- **Add Rule** based on last modified or created date
- **Conditions:** More than X days (e.g., 60 days)
- **Actions:** Move to cold/archive storage, then delete

**Blob Type Support:**
- **Block blobs** - Normal files
- **Append blobs** - Files to be appended (like logs)
- **Base blobs** - Snapshots and versions

**Important Considerations:**
- **Rehydration** required for archived blobs before access
- Data retention regulations compliance
- Filter options available (prefixes, containers, file extensions)

---

## Managing Storage Account Access Keys Using GUI

### Access Key Management

**Two Access Keys Available:**
- Connection strings for programmatic access
- Key rotation capability (rotate key 1 while key 2 users maintain access)
- **Best Practice:** Use Shared Access Signatures instead of full access keys

### Azure Storage Explorer

**Capabilities:**
- Manage storage account contents
- Access keys, blob containers, file shares
- Message queues and stored tables

**Use Cases:**
- Give developers/technicians full storage account access
- Alternative to creating Azure AD users with RBAC limitations
- **Note:** Shared Access Signatures provide subset access (more secure)

---

## Managing Storage Account Access Keys Using CLI

### PowerShell CLI Commands

**List Storage Account Keys:**
```bash
az storage account keys list --account-name storeasth334 --resource-group App1 --output table
```

**Renew/Regenerate Storage Account Keys:**
```bash
az storage account keys renew -g App1 -n storeasth334 --key primary
```

---

## Managing Storage Account Access Keys Using PowerShell

### PowerShell Commands

**Discover Available Commands:**
```powershell
Get-Command *storage*key*
```

**List Storage Account Keys:**
```powershell
Get-AzStorageAccountKey -ResourceGroupName app1 -Name storeasth33
```

**Get Specific Key Value:**
```powershell
(Get-AzStorageAccountKey -ResourceGroupName app1 -Name storeasth33).Value[0]  # Primary key
(Get-AzStorageAccountKey -ResourceGroupName app1 -Name storeasth33).Value[1]  # Secondary key
```

**Renew/Regenerate Storage Account Keys:**
```powershell
New-AzStorageAccountKey -ResourceGroupName app1 -Name storeasth33 -KeyName key2
```

---

## Managing Storage Account Shared Access Signatures (SAS)

### Account-Level SAS

**Navigation:** `Storage Account → Overview → Security + Networking → Shared Access Signatures`

**Configuration Options:**
- Define allowed services (Blob, File, Queue, Table)
- Set permissions and time limits
- Specify allowed IP addresses
- Generate SAS URL for restricted access

**Usage:**
- Copy blob service SAS URL
- Paste in Storage Explorer for limited access

---

## Managing Blob Shared Access Signatures

### Blob-Level SAS

**Navigation:** `Storage Account → Container → Click Blob → Generate SAS`

**Configuration:**
- Choose signing key (key1 or key2)
- Set start and expiry time
- Limit by IP address
- Define specific permissions

**Security Benefits:**
- Granular access control
- Time-limited access
- IP address restrictions
- No need to share full account keys

---

## Managing Access to Azure Tables

### Azure Tables Overview

**Navigation:** `Storage Account → Data Storage → Tables`

**Functionality:**
- Stores key-value pairs
- NoSQL data storage
- Scalable and fast queries

**Access Control:**
- Set up access policies
- Generate SAS tokens for table access
- Use SAS in Storage Explorer to view table data

---

## Using Azure Storage Explorer

### Features and Capabilities

- GUI-based storage management
- Connect using various authentication methods
- Browse and manage all storage types
- Upload, download, and organize data
- Support for SAS token connections

---

## Attaching a Managed Disk to a VM

### Attachment Process

**Prerequisites:**
- VM does not have to be running during attachment
- Create data disk (not OS disk)

**Configuration:**
- **LUN:** 0 (Logical Unit Number)
- **Type:** Premium SSD (or as required)
- **Size:** As needed (e.g., 50 GB)
- Save configuration

### OS-Level Configuration

**After Attachment (Windows):**
1. RDP into machine
2. Start button → "Create and format hard disk partitions"
3. Initialize disk (GPT recommended)
4. Right-click unallocated volume → New simple volume
5. Complete volume creation wizard

**Snapshot Capabilities:**
- Create snapshots from disk resource
- Use as starting point for additional disks
- Enable point-in-time recovery

---

## AZ-500 Practice Questions & Answers

### Question Set 1: Versioning and Deletion

**Q1: What happens when a blob is deleted and storage account versioning is enabled?**
- ❌ Delete blobs and versions are automatically archived
- ❌ The blob and its versions are deleted
- ❌ Blobs cannot be deleted when versioning is enabled
- ✅ **Previous blob versions persist**

### Question Set 2: Access Control

**Q2: How is a shared access signature (SAS) different from a storage account access key?**
- ❌ The storage account key can provide time-limited access to a storage account
- ✅ **The SAS can provide access to a subset of storage account objects**
- ❌ The storage account key can provide access to a subset of storage account objects
- ❌ The SAS can provide time-limited access to a storage account

### Question Set 3: PowerShell Commands

**Q3: Which PowerShell expression retrieves the primary key from a storage account?**
- ❌ `(Get-AzStorageAccountKey -ResourceGroupName app1 -Name storacct1).Primary[0]`
- ❌ `(Get-AzStorageAccountKey -ResourceGroupName app1 -Name storacct1).Primary`
- ✅ **`(Get-AzStorageAccountKey -ResourceGroupName app1 -Name storacct1).Value[0]`**
- ❌ `Get-AzStorageAccountKey -ResourceGroupName app1 -Name storacct1.Value[0]`

### Question Set 4: Azure Tables

**Q4: With Azure Tables, which term is equivalent to a database row for a SQL table entry?**
- ❌ Attribute
- ❌ Property
- ❌ Schema
- ✅ **Entity**

### Question Set 5: CLI Commands

**Q5: You need to renew the primary key for storage account named storacct1. What is missing from the following CLI expression?**
```bash
az storage account keys renew -g app1 -n storaccteastyhz7762
```
- ❌ "az storage account" should be "az storage keys"
- ✅ **The "--key primary" parameter and value are missing**
- ❌ The specified storage account name is incorrect
- ❌ The "-g" parameter is invalid

### Question Set 6: Immutable Storage

**Q6: You would like to implement immutable blob storage and have the option to turn off immutability as needed. Which items must be configured?**
- ✅ **Time-based retention**
- ✅ **Immutability support must be enabled during the storage account creation process**
- ❌ Immutability support must be enabled after the storage account is created
- ❌ Legal hold

### Question Set 7: Key Rotation

**Q7: Why do storage accounts have two access keys?**
- ✅ **Either key can be used while the other is rotated**
- ❌ Both are required when accessing the storage account
- ❌ Only rotated keys can be used to access the storage account
- ❌ Each key can be used only within a specific time frame

### Question Set 8: Network Security

**Q8: Which network access options are available when securing storage accounts?**
- ❌ Enabled from private networks
- ✅ **Enabled from all networks**
- ❌ Enabled from public networks
- ✅ **Enabled from selected virtual networks and IP addresses**

### Question Set 9: Lifecycle Management

**Q9: Storage account lifecycle rules can apply to which blob subtypes?**
- ✅ **Base blobs**
- ✅ **Block blobs**
- ✅ **Snapshots**
- ✅ **Append blobs**

### Question Set 10: Soft Delete

**Q10: What is the storage account soft delete default purge interval?**
- ✅ **7 days**
- ❌ 1 hour
- ❌ 24 hours
- ❌ 3 days

### Question Set 11: SAS Configuration

**Q11: Which items can be specified when creating a blob shared access signature?**
- ❌ RBAC role
- ❌ Allow/Deny access
- ✅ **Signing key**
- ✅ **Allowed IP addresses**

### Question Set 12: Managed Disks

**Q12: What must technicians do before an attached managed disk can be utilized within the VM operating system?**
- ✅ **The disk must be initialized, partitioned and formatted**
- ❌ The disk must only be partitioned
- ❌ The disk must only be formatted
- ❌ The disk is automatically mounted

### Question Set 13: Storage Explorer

**Q13: Which types of Azure items can be managed using Storage Explorer?**
- ❌ RDS Databases
- ❌ Virtual machines
- ❌ Resource groups
- ✅ **Storage accounts**

---

## Key Takeaways for AZ-500

### Critical Concepts

**Data Protection:**
- Versioning preserves previous blob versions when deleted
- Soft delete provides recovery window (default 7 days)
- Immutable storage prevents modification/deletion for compliance

**Access Control:**
- Two access keys enable key rotation without service interruption
- SAS tokens provide granular, time-limited access
- Network restrictions can limit access to specific VNets/IPs

**PowerShell Key Management:**
- Use `.Value[0]` for primary key, `.Value[1]` for secondary key
- `New-AzStorageAccountKey` for key regeneration
- `Get-AzStorageAccountKey` for key retrieval

**CLI Commands:**
- `az storage account keys renew --key primary` for key rotation
- Missing `--key` parameter is common exam trap
- Use `--output table` for readable format

**Storage Lifecycle:**
- Automatic tier transitions based on age/access patterns
- Archive tier requires rehydration before access
- Lifecycle rules apply to all blob types (block, append, base)

**Security Best Practices:**
- Use SAS tokens instead of full access keys when possible
- Implement network restrictions for sensitive data
- Enable versioning and soft delete for data protection
- Regular key rotation for enhanced security