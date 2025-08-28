# Azure Files

## Overview

### Access Methods

**File Share Protocols:**
- **SMB** (Server Message Block) - Windows native
- **NFS** (Network File System) - Linux/Unix native
- Can have both protocols within the same storage account
- A single shared folder cannot be both SMB and NFS simultaneously

### Naming Convention

**File Share URL Structure:**
```
StorageAccountName.file.core.windows.net\sharename
```

### Key Configuration Options

**Quota:**
- Set in GB
- Defines maximum size the file share can grow to

**Storage Tiers:**
- Transaction optimized, Hot, Cold storage options

**Placement:**
- Can run in cloud or on-premises
- Requires access through firewall
- **Requires port 445 outbound**

**Critical:** Port 445 must be open for SMB file share access

---

## Managing File Shares with the Portal

### Navigation Path
`Storage Accounts → Data Storage → File Share`

### Storage Tiers

**Transaction Optimized (Default tier):**
- For heavy workloads
- Great for applications requiring file storage as backend store
- Best performance for high transaction scenarios

**Hot (General Purpose):**
- Team shares
- File synchronization
- Frequently accessed data

**Cold (Archive Storage):**
- Online archive storage
- Infrequently accessed data
- Lower storage costs

### Additional Features

**Backup and Recovery:**
- Create snapshots for point-in-time recovery
- Configure backup policies
- Enable versioning for file recovery

**Connection Methods:**
- Portal generates OS-specific connection scripts
- Supports Windows, Linux, and macOS
- Provides PowerShell, CLI, and GUI options

---

## Managing File Shares with CLI

### Initial Setup

**List Storage Accounts:**
```bash
az storage account list --query [].name
```

**Get Storage Account Keys:**
```bash
az storage account keys list --account-name storaccteast3432 --resource-group App1 --output table
```

**Set Variables:**
```bash
$az-storage-account="storacct234523"
$azstorageaccesskey="/345sert35ser=="
```

### File Share Operations

**Create a File Share:**
```bash
az storage share create --name fileshare1 --account-key $azstorageaccesskey --account-name $az-storage-account
```
*Returns: true if successful*

**List File Share Details:**
```bash
az storage share list --account-key $azstorageaccesskey --account-name $az-storage-account
```

**List Only Share Names:**
```bash
az storage share list --account-key $azstorageaccesskey --account-name $az-storage-account --query [].name
```

### File Operations

**Upload a File:**
1. Click **Upload** to load file into cloud shell
2. Run `dir` to verify file presence
3. Execute upload command:
```bash
az storage file upload --account-key $azstorageaccesskey --account-name $az-storage-account --share-name fileshare1 --source ./Project_A.txt
```

**List Files in Share:**
```bash
az storage file list --account-key $azstorageaccesskey --account-name $az-storage-account --share-name fileshare1 --query [].name
```

---

## Managing File Shares with PowerShell

### Drive Mapping Script

**Network Connectivity Test and Drive Mapping:**
```powershell
$connectTestResult = Test-NetConnection -ComputerName storaccthql.file.core.windows.net -Port 445

if ($connectTestResult.TcpTestSucceeded) {
    # Save the password so the drive will persist on reboot
    cmd.exe /C "cmdkey /add:`"storaccthql.file.core.windows.net`" /user:`"localhost\storaccthql`" /pass:`"j5r026G0i971WiEY0hGTOJkEuM3S7wyQNfS9aE2gBzivcwcFp1Km3uXCL313S==`""
    
    # Mount the drive
    New-PSDrive -Name Z -PSProvider FileSystem -Root "\\storaccthql.file.core.windows.net\budgets" -Persist
} else {
    Write-Error -Message "Unable to reach the Azure storage account via port 445. Check to make sure your organization or ISP is not blocking port 445, or use Azure P2S VPN, Azure S2S VPN, or Express Route to tunnel SMB traffic over a different port."
}
```

**Verify Drive Mapping:**
```powershell
Get-PSDrive
```

### Storage Context Operations

**Create Storage Context:**
```powershell
$ctx = Get-AzStorageAccount -ResourceGroupName App1 -Name storacct234f
$ctx
$ctx = $ctx.Context
$ctx
```
*Note: Context contains various endpoints for different services in the storage account*

### File Share Management

**Create New File Share:**
```powershell
New-AzStorageShare -Name "fileshare2" -Context $ctx
```

**Get File Share:**
```powershell
Get-AzStorageShare -Name "fileshare2" -Context $ctx
```

**Upload File:**
```powershell
Set-AzStorageFileContent -ShareName "fileshare2" -Source "./projectA.txt" -Context $ctx
```

**List Files in Share:**
```powershell
Get-AzStorageFile -ShareName "fileshare2" -Context $ctx
```

**Download File:**
```powershell
Get-AzStorageFileContent -ShareName "fileshare2" -Path "./projectA.txt" -Context $ctx
```
*Prompts: Yes to overwrite existing files*

---

## Mapping File Share with Windows

### Portal Method
Navigate to **Storage Account → Connect to SMB**

### Command Line Method

**Add Credentials:**
```cmd
cmdkey /add:storacct5663.file.core.windows.net /user:Azure\storacct3453 /pass:54j==
```
*Output: CMDKEY: Credential added successfully.*

**Map Network Drive:**
```cmd
net use Z: \\storacct44889.file.core.windows.net\projects /persistent:Yes
```
*Prompt: Do you want to overwrite the remembered connection? (Y/N) y*

**Verify Mapping:**
```cmd
net use
```

---

## Mapping File Share with Linux

### Mount Point Setup

**Create Mount Directory:**
```bash
sudo mkdir /mnt/budgets
```
*Access this folder to access file share contents*

### Credential Configuration

**Setup SMB Credentials:**
```bash
if [ ! -f "/etc/smbcredentials/storaccthql.cred" ]; then
    sudo bash -c 'echo "username=storaccthql" >> /etc/smbcredentials/storaccthql.cred'
    sudo bash -c 'echo "password=IWiEYOhGTOJkEuM3S7WYQNfS9aE2g8ZiVCWCFPIKm3uXCL313S40RY/dTeoxtJP==" >> /etc/smbcredentials/storaccthql.cred'
fi

sudo chmod 600 /etc/smbcredentials/storaccthql.cred
```

### Persistent Mount Configuration

**Add to fstab for Persistence:**
```bash
sudo bash -c 'echo "//storaccthql.file.core.windows.net/budgets /mnt/budgets cifs nofail,vers=3.0,credentials=/etc/smbcredentials/storaccthql.cred,dir_mode=0777,file_mode=0777,serverino" >> /etc/fstab'
```

**Mount the File Share:**
```bash
sudo mount -t cifs //storaccthql.file.core.windows.net/budgets /mnt/budgets -o vers=3.0,credentials=/etc/smbcredentials/storaccthql.cred,dir_mode=0777,file_mode=0777,serverino
```

### Navigation and Management

**Access Mount Point:**
```bash
$ ls /
cd /mnt && ls
cd budgets
ls
cd /
```

**Unmount File Share:**
```bash
sudo umount /mnt/budgets
cd /mnt/budgets
```

**Check Persistence Configuration:**
```bash
sudo tail /etc/fstab
```

---

## AZ-500 Practice Questions & Answers

### Question Set 1: Network and Configuration

**Q1: Which TCP port must be open to map a drive to an Azure Files shared folder?**
- ❌ 3389
- ❌ 80
- ✅ **445**
- ❌ 443

**Q2: Where are Azure Files shared folders configured in Azure?**
- ❌ Virtual machine
- ❌ Azure Blueprint
- ✅ **Storage account**
- ❌ Web app

### Question Set 2: CLI Commands

**Q3: Which CLI command shows files in an Azure Files shared folder?**
- ❌ az storage share list
- ❌ az storage account list
- ✅ **az storage file list**
- ❌ az storage account keys list

### Question Set 3: Backup and Recovery

**Q4: You need to ensure deleted files in an Azure Files shared folder can be easily recovered by end-users. What should you do?**
- ❌ Enable a storage account time-based retention policy
- ❌ Enable a storage account legal hold policy
- ✅ **Take shared folder snapshots**
- ❌ Enable storage account versioning

### Question Set 4: Linux Administration

**Q5: Which Linux command runs commands with elevated permissions?**
- ✅ **sudo**
- ❌ echo
- ❌ mkdir
- ❌ chmod

### Question Set 5: PowerShell Syntax

**Q6: What is wrong with the following PowerShell expression?**
```powershell
New-AzStorageShare -Name "fileshare2"
```

- ❌ Location was not specified
- ❌ File share names cannot contain numbers
- ✅ **-Context was not specified**
- ❌ File share names must be uppercase

---

## Key Takeaways for AZ-500

### Critical Concepts

**Network Requirements:**
- Port 445 must be open for SMB access
- Alternative: Use VPN tunneling if port 445 is blocked
- Test connectivity before attempting file share mapping

**Storage Tiers:**
- Transaction Optimized: Best for high-workload scenarios
- Hot: General purpose, team collaboration
- Cold: Archive and infrequently accessed data

**Security Considerations:**
- Use strong access keys and rotate regularly
- Implement snapshots for data recovery
- Consider network security for on-premises access
- Use managed identities where possible

**Management Methods:**
- Portal: GUI-based, generates connection scripts
- CLI: Scriptable, good for automation
- PowerShell: Windows-centric, context-based operations
- Direct OS commands: Platform-specific implementation

**Cross-Platform Support:**
- Windows: Native SMB, cmdkey, net use
- Linux: CIFS mounting, credential files, fstab persistence
- Both: Require proper authentication and network connectivity