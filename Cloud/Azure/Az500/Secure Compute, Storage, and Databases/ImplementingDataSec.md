Encryption

SQL TDE, Storage account encryption
VPN
TLS
AZ key vault creation, EC maybe slightly quicker


Data Privacy and regulations
Pii,gpdr


Classifying Data using MS Purview Governance
To scan, searching for sensitive data, Create a Purview resource/account, 
Governance portal - where you do bulk of the data classification
Purview needs role access to read blobs. 
    • Choose add role assignment>storage blob data reader > IAM> user, group, or service principal > select member "resource" purview > check IAM > see map view > scan button - to configure scan 
    

Enabling Dynamic Data Masking
Looking at a sql server > data masking, add mask. 
Look at what will be displayed. Choose how to mask. At bottom choose masking field format
Sql users excluded-admin will always be able to see anything 



Azure Disk Encryption (ADE)
ADE-integrates with Az Key Vault-AKV,needs to be in the same region as VM


For Windows
$KeyVault = Get—AzKeyVau1t —VaultName MyKV -ResourceGroupName MyResourceGroup 

Set—AzVMDiskEncryptionExtension —ResourceGroupName MyResourceGroup —VMName MyVM —DiskEncryptionKeyVauItUrI 
$KeyVault.VaultUri —DiskEncryptionKeyVaultId $KeyVault.Resourceld 

Get-AzVmDiskEncryptionStatus -VMName winSrv2019 -ResourceGroup app1

For Linux
$KeyVault = Get—AzKeyVau1t —VaultName MyKV -ResourceGroupName MyResourceGroup 

Set—AzVMDiskEncryptionExtension —ResourceGroupName MyResourceGroup —VMName MyVM —DiskEncryptionKeyVauItUrI 
$KeyVault.VaultUri —DiskEncryptionKeyVaultId $KeyVault.Resourceld -SkipVmBackup -VolumeType All



Managing ADE
On server, see vm-extensions, to see if key vault shows up
Don’t manage the encryption through the vm, only through Azure

Encrypting Storage Accounts
Go to storage account view, properties, security, encryption, if compliance says keys needs to be
Under your control, select "customer-managed", select key vauly, system, save

If your having trouble with key, may need to adjust or create a key access policy


Enabling SQL Transparent Data Encryption (TDE)
Choose sqldb > tde, customer-managed key, select "make this key the default tde protecter"




Enabling VM Disk Encryption
Create a resource, marketplace, managed disk, choose encryption
Can change from platform managed key to custom managed key


Public Key Infrastructure (PKI)
Can import or create a pki cert in Az KV



SSL and TLS



Enabling Web app HTTPS Connectivity



TEST

Which network security protocol does TLS supersede?

Ipsec
SSL
PPTP
PGP

Which data sensitivity regulation applies to European Union citizen’s private data?

HIPAA
GDPR
PIPEDA
PCI DSS

You plan on enabling Azure Disk Encryption (ADE) for a Windows virtual machine running in Microsoft Azure. What is used to encrypt VM disks?

Microsoft BitLocker
dm-crypt
Transport Layer Security (TLS)
Encrypting File System (EFS)


Which PowerShell cmdlet is used to enable Azure Disk Encryption (ADE) for a virtual machine?

Set-AzKeyVault
Get-AzKeyVault
Get-AzVmDiskEncryptionExtension
Set-AzVmDiskEncryptionExtension


Which PKI component issues certificates?

Private key
Public key
Management group
Certification authority

You would like to automate the scanning and classification of existing storage account blobs. What is the first thing you should do?

Create a managed identity
Create an RBAC role assignment
Create a new storage account
Create a Purview account


Which Azure prerequisite must be met before creating a customer-managed key?

New Azure AD tenant
Storage account
Key vault
Management group


You have enabled data masking for an Azure SQL database deployment. When you sign in with your Azure admin account, masked data shows up in plain text. What is the problem?

Database transparent data encryption (TDE) is not enabled
The incorrect RBAC role assignment was made on the Azure SQL server instance
A customer-managed key was not configured for the database
There is no problem; admin users always see masked data


Which key is normally used for decryption?

Public
Symmetric
Asymmetric
Private

Which SQL items are protected with SQL TDE?

Logs
Enterprise apps
Database
Azure AD accounts

What is the default HTTPS listening port number?

443
389
3389
80

Which type of Azure resource is required to enable encryption for managed disks?

Storage account
Virtual machine
Load balancer
Disk encryption set