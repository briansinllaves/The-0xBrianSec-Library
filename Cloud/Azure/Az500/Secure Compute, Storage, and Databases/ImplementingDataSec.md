# Encryption & Data Privacy

## Core Encryption Technologies

### Overview of Azure Encryption Services

**Key Azure Encryption Technologies:**
- **SQL TDE** (Transparent Data Encryption)
- **Storage Account Encryption**
- **VPN Encryption**
- **TLS** (Transport Layer Security)
- **Azure Key Vault** - centralized key management (EC keys may be slightly quicker)

---

## Data Privacy and Regulations

### Key Regulations

**PII (Personally Identifiable Information):**
- Any data that can identify an individual
- Must be protected according to regional regulations

**GDPR (General Data Protection Regulation):**
- Applies to European Union citizens' private data
- Requires explicit consent and data protection measures
- Significant penalties for non-compliance

**AZ-500 Focus:** Understanding GDPR requirements is crucial for Azure deployments serving EU citizens

---

## Classifying Data using Microsoft Purview Governance

### Setup Process

**Step 1: Create Purview Resource**
1. Create a Purview resource/account in Azure
2. Access the **Governance Portal** - where you perform bulk data classification

### Configuring Purview Access

**Role Assignment for Blob Scanning:**
Purview needs role access to read blobs for data discovery and classification.

**Steps:**
1. Navigate to **Storage Account → IAM**
2. Choose **Add Role Assignment**
3. Select **Storage Blob Data Reader** role
4. Under **Assign Access To:** choose **User, group, or service principal**
5. **Select Member:** Choose your Purview resource
6. **Verify:** Check IAM to confirm assignment
7. **Scan Configuration:** Use Map View → Scan button to configure scanning

### Data Scanning and Classification

- Purview automatically scans for sensitive data patterns
- Creates data maps showing sensitive data locations
- Applies automatic classification based on data content
- Provides compliance reporting and governance insights

---

## Enabling Dynamic Data Masking

### Configuration Process

**Navigation:** `SQL Server → Data Masking → Add Mask`

### Masking Options

**Available Masking Types:**
- **Default masking** - Full field masking with X's
- **Email masking** - Shows first character and domain
- **Random number** - Generates random numbers within range
- **Custom text** - Custom masking pattern

**Configuration:**
1. Select fields to mask
2. Choose masking field format at bottom of configuration
3. Preview what will be displayed to users

**Important:** SQL users excluded from masking - admin users will always see unmasked data

### Masking Behavior

**Admin Access:**
- Database administrators always see plain text data
- This is expected behavior, not a configuration issue
- Masking only applies to non-privileged users

---

## Azure Disk Encryption (ADE)

### Prerequisites

**Key Requirements:**
- **Azure Key Vault (AKV)** integration required
- Key Vault **must be in the same region** as the VM
- Proper access policies configured

### Windows VM Encryption

```powershell
# Get Key Vault reference
$KeyVault = Get-AzKeyVault -VaultName MyKV -ResourceGroupName MyResourceGroup

# Enable disk encryption
Set-AzVMDiskEncryptionExtension -ResourceGroupName MyResourceGroup -VMName MyVM -DiskEncryptionKeyVaultUri $KeyVault.VaultUri -DiskEncryptionKeyVaultId $KeyVault.ResourceId

# Check encryption status
Get-AzVmDiskEncryptionStatus -VMName winSrv2019 -ResourceGroup app1
```

### Linux VM Encryption

```powershell
# Get Key Vault reference
$KeyVault = Get-AzKeyVault -VaultName MyKV -ResourceGroupName MyResourceGroup

# Enable disk encryption for Linux
Set-AzVMDiskEncryptionExtension -ResourceGroupName MyResourceGroup -VMName MyVM -DiskEncryptionKeyVaultUri $KeyVault.VaultUri -DiskEncryptionKeyVaultId $KeyVault.ResourceId -SkipVmBackup -VolumeType All
```

**Linux-Specific Parameters:**
- `-SkipVmBackup` - Skips VM backup requirement
- `-VolumeType All` - Encrypts all volume types

### Managing ADE

**Best Practices:**
- View encryption status in **VM → Extensions** to see if Key Vault integration is active
- **Don't manage encryption through the VM directly** - only through Azure portal/PowerShell
- Monitor encryption progress and status regularly

**Encryption Technology:**
- **Windows:** Uses Microsoft BitLocker
- **Linux:** Uses dm-crypt

---

## Encrypting Storage Accounts

### Customer-Managed Keys

**Configuration Path:** `Storage Account → Properties → Security → Encryption`

**Steps for Customer-Managed Keys:**
1. **Check compliance requirements** - if keys need to be under your control
2. Select **"Customer-managed"** option
3. **Select Key Vault** and choose your key
4. **System assignment** for managed identity
5. **Save** configuration

### Troubleshooting Key Access

**Common Issues:**
- Key access policy may need adjustment
- Managed identity permissions
- Key Vault firewall settings

**Resolution:**
- Create or update Key Vault access policy
- Verify managed identity has proper Key Vault permissions

---

## Enabling SQL Transparent Data Encryption (TDE)

### Configuration Process

**Navigation:** `SQL Database → TDE`

**Customer-Managed Key Setup:**
1. Select **"Customer-managed key"** option
2. Choose your Key Vault and key
3. Select **"Make this key the default TDE protector"**
4. Apply configuration

### What TDE Protects

**TDE Encrypts:**
- Database files
- Log files
- Backup files
- Database at rest

**Key Point:** TDE protects data at rest, not data in transit or in memory

---

## Enabling VM Disk Encryption

### Managed Disk Encryption

**Creation Process:**
1. **Create Resource** → Marketplace → **Managed Disk**
2. **Choose Encryption Type:**
   - Platform-managed key (default)
   - Customer-managed key (requires Key Vault)

### Disk Encryption Set

**Prerequisites:**
- **Disk Encryption Set** resource required for customer-managed keys
- Links managed disks to Key Vault keys
- Enables centralized key management

---

## Public Key Infrastructure (PKI)

### Azure Key Vault PKI Support

**Certificate Management:**
- **Import existing PKI certificates** into Azure Key Vault
- **Create new certificates** within Key Vault
- Automated certificate renewal
- Integration with Azure services

**Certificate Types:**
- Self-signed certificates
- CA-signed certificates
- Integration with external CAs

---

## SSL and TLS

### Protocol Hierarchy

**TLS supersedes SSL:**
- **TLS** (Transport Layer Security) is the modern standard
- **SSL** (Secure Sockets Layer) is the deprecated predecessor
- Current versions: TLS 1.2 and TLS 1.3

### Default Ports

| Protocol | Port | Usage |
|----------|------|-------|
| **HTTPS** | 443 | Secure web traffic |
| **HTTP** | 80 | Unsecured web traffic |
| **LDAP** | 389 | Directory services |
| **RDP** | 3389 | Remote desktop |

### Key Types and Usage

| Key Type | Primary Use |
|----------|-------------|
| **Private Key** | Decryption, digital signatures |
| **Public Key** | Encryption, signature verification |
| **Symmetric Key** | Fast encryption/decryption of data |
| **Asymmetric Key** | Key exchange, digital signatures |

---

## Enabling Web App HTTPS Connectivity

### HTTPS Configuration

**Azure App Service HTTPS:**
- Automatic HTTPS redirect configuration
- Custom domain SSL/TLS certificate binding
- Managed certificates for custom domains
- App Service Certificate integration

**Best Practices:**
- Always enforce HTTPS for production applications
- Use TLS 1.2 minimum
- Configure HTTP to HTTPS redirects
- Implement HSTS headers

---

## AZ-500 Practice Questions & Answers

### Question Set 1: Protocol & Regulation Knowledge

**Q1: Which network security protocol does TLS supersede?**
- ❌ IPsec
- ✅ **SSL**
- ❌ PPTP  
- ❌ PGP

**Q2: Which data sensitivity regulation applies to European Union citizen's private data?**
- ❌ HIPAA
- ✅ **GDPR**
- ❌ PIPEDA
- ❌ PCI DSS

### Question Set 2: Azure Disk Encryption

**Q3: You plan on enabling Azure Disk Encryption (ADE) for a Windows virtual machine. What is used to encrypt VM disks?**
- ✅ **Microsoft BitLocker**
- ❌ dm-crypt
- ❌ Transport Layer Security (TLS)
- ❌ Encrypting File System (EFS)

**Q4: Which PowerShell cmdlet is used to enable Azure Disk Encryption (ADE)?**
- ❌ Set-AzKeyVault
- ❌ Get-AzKeyVault
- ❌ Get-AzVmDiskEncryptionExtension
- ✅ **Set-AzVmDiskEncryptionExtension**

### Question Set 3: PKI & Data Classification

**Q5: Which PKI component issues certificates?**
- ❌ Private key
- ❌ Public key
- ❌ Management group
- ✅ **Certification authority**

**Q6: You would like to automate scanning and classification of existing storage account blobs. What should you do first?**
- ❌ Create a managed identity
- ❌ Create an RBAC role assignment
- ❌ Create a new storage account
- ✅ **Create a Purview account**

### Question Set 4: Customer-Managed Keys & Data Masking

**Q7: Which Azure prerequisite must be met before creating a customer-managed key?**
- ❌ New Azure AD tenant
- ❌ Storage account
- ✅ **Key vault**
- ❌ Management group

**Q8: You enabled data masking for Azure SQL database. When you sign in with your admin account, masked data shows in plain text. What is the problem?**
- ❌ Database transparent data encryption (TDE) is not enabled
- ❌ The incorrect RBAC role assignment was made
- ❌ A customer-managed key was not configured
- ✅ **There is no problem; admin users always see masked data**

### Question Set 5: Encryption Fundamentals

**Q9: Which key is normally used for decryption?**
- ❌ Public
- ❌ Symmetric
- ❌ Asymmetric
- ✅ **Private**

**Q10: Which SQL items are protected with SQL TDE?**
- ❌ Logs
- ❌ Enterprise apps
- ✅ **Database**
- ❌ Azure AD accounts

**Q11: What is the default HTTPS listening port number?**
- ✅ **443**
- ❌ 389
- ❌ 3389
- ❌ 80

**Q12: Which type of Azure resource is required to enable encryption for managed disks?**
- ❌ Storage account
- ❌ Virtual machine
- ❌ Load balancer
- ✅ **Disk encryption set**

---

## Key Takeaways for AZ-500

### Critical Concepts

**Encryption Hierarchy:**
1. **Data at Rest:** TDE, Storage Encryption, Disk Encryption
2. **Data in Transit:** TLS/SSL, VPN
3. **Data in Processing:** Always Encrypted, confidential computing

**Key Management:**
- Azure Key Vault is central to most encryption scenarios
- Customer-managed keys require Key Vault
- Regional proximity important for performance

**Compliance:**
- GDPR applies to EU citizen data regardless of where processed
- Data classification with Purview is essential for compliance
- Dynamic data masking protects against casual exposure

**PowerShell Commands:**
- `Set-AzVmDiskEncryptionExtension` for ADE
- `Get-AzVmDiskEncryptionStatus` for status checking
- Key Vault integration required for most encryption scenarios