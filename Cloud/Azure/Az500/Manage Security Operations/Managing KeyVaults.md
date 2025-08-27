## Creating Key Vault

 What is Azure Key Vault?
    • A secure service to store:
        ○ Credentials, passwords, database connection strings
        ○ PKI certificates
        ○ Secrets used by apps and services
    • Supports centralized secret management

💡 Key Vault Use Case
    • Encrypt Azure VM disks using customer-managed keys
    • 🔑 Store encryption keys in the same Azure region as the VM

🛠️ Creating a Key Vault (Portal)
    1. Go to Create a resource
    2. Search for: Key Vault
    3. Select Key Vault by Microsoft → Click Create
    4. Choose:
        ○ Resource Group (e.g., App1)
        ○ Key Vault Name (e.g., KVEast1)
        ○ Region (e.g., East US)
            § Must match the region of associated services like VMs

🌍 Common Azure Regions
    • East US 2
    • Germany West Central
    • France Central
    • Japan East/West
    • Korea Central/South

💲 Pricing Tier
    • Standard: No HSM support
    • Premium: Includes Hardware Security Module (HSM)
        ○ Required for tamper-resistant key storage
        ○ Supports cryptographic operations

🧹 Soft Delete & Retention Settings
    • Soft delete is enabled by default: 90-day recovery window
    • You can:
        ○ Enable purge protection (cannot delete during retention)
        ○ Disable purge protection (can delete within retention)
    • After setting, click Review + Create and Create

🧑‍💻 Post-Creation: Access Configuration
    • Click Go to Resource to open the vault
    • Under Access Policies:
        ○ Assign access to users/services (e.g., IT Demo 5)
        ○ Click + Create to define policies

📋 Access Policy Templates
    • Key, Secret & Certificate Management
    • Secret Management only
    • SQL Server Connector
    • Azure Storage / Data Lake
    • Exchange/SharePoint Customer Keys
    • Azure Info Protection BYOK
    • M365 Data at Rest Encryption

🧑 Assigning Users/Apps
    • Choose a user (e.g., Abu Adachi)
    • Optionally assign an app to access the vault
    • Click Next → Create

🔒 Role-Based Access Control (IAM)
    • Navigate: Access Control (IAM) → + Add role assignment
    • Example roles:
        ○ Key Vault Administrator: Full control
        ○ Key Vault Contributor: Manage vault but not contents
        ○ Key Vault Reader: Read-only access to settings
        ○ Other roles:
            § Key Vault Certificates Officer
            § Key Vault Crypto Officer
            § Key Vault Crypto Service Encryption User
            § Key Vault Crypto User

🧱 Vault Object Management
    • Go to Properties > Objects
    • Manage:
        ○ 🔑 Keys
        ○ 🔐 Secrets
        ○ 📜 Certificates (PKI)

💻 Command Line Management
Azure CLI
az keyvault create --help
    • az keyvault create: Create a new key vault
    • Use flags like --name, --resource-group, --location, --sku
PowerShell
Get-Command *keyvault*
    • Lists all key vault-related cmdlets
    • Common: New-AzKeyVault, Set-AzKeyVaultAccessPolicy


## Managing Key Vault Secrets Using the GUI



🗂️ Accessing Existing Key Vault
    • Go to All Resources in Azure portal.
    • Filter by Type: Key vault → Click Apply.
    • Only appears if at least one vault exists (e.g., KVEast1 in East US).

🌍 Region Awareness
    • Resources needing the vault (e.g., VMs) should be in the same region.
    • Use multiple vaults for:
        ○ Regional separation
        ○ Isolated IT team control

🔐 Access Requirements
    • Required to manage secrets:
        ○ IAM Role Assignments (via Access Control)
        ○ Access Policies (fine-grained permissions)
    • Policies may include:
        ○ ✅ Key Permissions
        ○ ❌ Secret/Certificate Permissions (may be absent)
    • Applies to users or services (VMs, storage, etc.)

🔑 Managing Keys
    • Click Generate/Import:
        ○ Import: Use existing public/private key pair or backup.
        ○ Generate:
            § Choose type: RSA or EC (Elliptic Curve)
            § RSA sizes: 2048 (default), 3072, 4096
            § EC uses smaller key sizes for equivalent strength
    • Optional:
        ○ Activation Date
        ○ Expiration Date
        ○ Time Zone (e.g., (UTC-04:00) Atlantic Time)
    • Default: Key is Enabled
    • Consider setting rotation policy for security compliance.

🔒 Key Details
    • Select key (e.g., RSAKeyPair1) → Click Current Version
        ○ ✅ Download Public Key
        ○ ❌ Cannot download Private Key
            § Private key remains securely in the vault
            § Used for:
                □ 🔐 Decryption (when encrypted with the public key)
                □ ✍️ Digital Signature Creation
            § Public key used to verify signatures
    • Under "Permitted operations" → See options like Sign

🧬 Managing Secrets
    • Click Generate/Import → Choose Manual
        ○ Certificate option is deprecated
    • Use case:
        ○ Tokens, passwords, access keys, connection strings
    • Example:
        ○ Name: SecretValue1
        ○ Value: (entered manually)
    • Notes:
        ○ Must be single-line in GUI
        ○ Multi-line secrets → Use CLI or API
    • Same options as keys:
        ○ Activation/Expiration
        ○ Enable/Disable

✅ Secret is now saved (e.g., SecretValue1)
📌 PKI Certificates handled in separate demo

## Managing Key Vault Secrets Using the CLI

AZ-500 Study Notes: Managing Key Vault Secrets Using the CLI

📥 Environment Setup
    • Open Cloud Shell in the Azure portal
    • Switch to Bash for Linux-style variable handling (optional)
        ○ PowerShell also supports Azure CLI

🏗️ Creating a Key Vault via CLI
az keyvault create \
  --location eastus \
  --name KVEast2 \
  --resource-group App1 \
  --network-acls-ips <public_IP>
    • --location: Azure region for the vault
    • --name: Name of the Key Vault
    • --resource-group: Target RG
    • --network-acls-ips: IP(s) allowed to access (e.g., on-prem public IP)
    
✅ Vault is now accessible from defined IPs
🧭 Confirm via portal under All Resources → Filter Key vault

📋 List Key Vaults

az keyvault list --query [].name

    • Lists only names of all key vaults in the subscription

🔐 Create a Secret via CLI
az keyvault secret set \
  --name db1connection \
  --value "connectionstringsamplevalue" \
  --vault-name KVEast2
    • --name: Secret name
    • --value: Secret value
    • --vault-name: Target vault
    
📌 Use for:
    • Access tokens
    • DB connection strings
    • Secure app config values

🔎 List Secrets in Vault
az keyvault secret list --vault-name KVEast2
    • Lists all secrets with full metadata
Optional filter:
az keyvault secret list --vault-name KVEast2 --query [].name
    • Returns only names

🔑 Create a Key Pair via CLI
az keyvault key create \
  --name RSAKeyPair2 \
  --kty RSA \
  --protection software \
  --vault-name KVEast2
    • --name: Key name
    • --kty: Key type (e.g., RSA, EC, EC-HSM)
    • --protection: Storage type (software or HSM)
    • --vault-name: Vault to store the key

🔍 List Keys in Vault
az keyvault key list --vault-name KVEast2 --query [].name

    • Lists all key names in the specified vault
    

🔐 Key Details in Portal
    • Open KVEast2 → Keys → Select RSAKeyPair2 → CURRENT VERSION
        ○ View:
            § ✅ Permitted operations: Encrypt, Decrypt, Sign, Verify
            § ✅ Download public key
            § ❌ Private key remains vault-only

## Managing Key Vault Secrets Using PowerShell

AZ-500 Study Notes: Managing Key Vault Secrets Using PowerShell

⚙️ Creating a Key Vault with PowerShell
New-AzKeyVault `
  -Name "KVEast3" `
  -ResourceGroupName "App1" `
  -Location "East US" `
  -EnabledForDeployment
    • -EnabledForDeployment: Allows Azure resources like VMs to access the vault (e.g., for disk encryption)

📛 Common PowerShell Cmdlets
Get-Command *keyvault*
    • Lists all available Key Vault cmdlets:
        ○ New-AzKeyVault
        ○ Set-AzKeyVaultAccessPolicy
        ○ Set-AzKeyVaultSecret
        ○ Add-AzKeyVaultKey
        ○ Get-AzKeyVaultKey, etc.

🔐 Set Access Policy
Set-AzKeyVaultAccessPolicy `
  -VaultName "KVEast3" `
  -UserPrincipalName "cblackwell@quick24x7testing.onmicrosoft.com" `
  -PermissionsToSecrets all `
  -PermissionsToKeys all `
  -PermissionsToCertificates all `
  -PermissionsToStorage get
    • Grants Codey Blackwell full access to secrets, keys, certs
    • Storage permission (get) allows pulling from storage-linked vault

📋 List Key Vaults
Get-AzKeyVault
    • Lists all vaults in the subscription
    • Use Select-Object Name to limit output

🔐 Create a Secure Secret
$secretvalue = ConvertTo-SecureString "MySecurePass!" -AsPlainText -Force
    • Converts string to secure format in memory
$secret = Set-AzKeyVaultSecret `
  -VaultName "KVEast3" `
  -Name "password1" `
  -SecretValue $secretvalue
    • Stores secret in Key Vault named password1

🛠️ Fix Access Denied Issues
    • If Generate/Import is grayed out or errors occur:
        ○ Use Access policies in the portal
        ○ Add current user with full permissions to secrets, keys, certs

🔑 Create a Key Pair
Add-AzKeyVaultKey `
  -VaultName "KVEast3" `
  -Name "RSAKeyPair4" `
  -Destination "Software"
    • -Destination: "Software" for soft keys, "HSM" for hardware-backed
    • Optional:
        ○ -KeyType EC → Elliptic Curve

🔎 List Keys in Vault
Get-AzKeyVaultKey -VaultName "KVEast3"
Filter to show only names:
Get-AzKeyVaultKey -VaultName "KVEast3" | Select-Object Name

## Managing Key Vault Certificates Using the GUI

Overview
    • Azure Key Vault can store:
        ○ Passwords
        ○ Key pairs (public/private)
        ○ PKI certificates (e.g., for HTTPS on custom domains)

Accessing the Key Vault
    1. Go to All Resources
    2. Filter Type to show only Key vault
    3. Open vault (e.g., KVEast3)

Certificate Creation Options
Click Certificates → Generate/Import
Method of Certificate Creation:
    • Generate: Create a new certificate within Azure
    • Import: Upload an existing certificate (e.g., PFX)

Certificate Authority (CA) Types
    1. Self-signed certificate
        ○ Signed by the vault itself
        ○ Not trusted by browsers unless root CA is installed
    2. Certificate issued by integrated CA
        ○ Requires setting up with providers like DigiCert or GlobalSign
        ○ Must provide account credentials (Account ID, Password, Org ID)
    3. Certificate issued by non-integrated CA
        ○ Generates a Certificate Signing Request (CSR)
        ○ Submit CSR externally to a CA (manual trust chain)
        ○ Not managed by KV

Example: Creating a Self-Signed Certificate
    • Name: Self-signed Certificate1
    • Common Name (CN): www.webapp1test.com
    • Add DNS name (must match CN for browser trust)
    • Validity: 12 months
    • Auto-Renewal:
        ○ Option: Renew at 80% lifetime
        ○ Alternative: Set reminder emails
    • Public/private key pair is auto-generated

Advanced Policy Configuration
    • Accessed via Not configured link during creation
    • Set:
        ○ Key Usage Flags (e.g., Digital Signature, Key Encipherment)
        ○ Key type: RSA or EC (Elliptic Curve)
        ○ Key size: 2048, 3072, 4096
        ○ Exportable private key: Enabled or Disabled
        ○ Certificate Transparency: Enabled by default

After Creation
    • Certificate appears immediately
    • Initial status: Disabled → auto-transitions to Enabled
    • Can now be used by:
        ○ Web apps (App Services)
        ○ VMs (using managed identity)

Permissions Reminder
    • The service (e.g., web app) must have access to Key Vault
        ○ Either through:
            § Access Policies
            § Role-Based Access Control (RBAC) via Access Configuration

## Managing Key Vault Certificates Using the CLI

AZ-500 Study Notes: Managing Key Vault Certificates Using the CLI

Viewing Key Vaults in CLI
az keyvault list
    • Lists all Key Vaults in the subscription
az keyvault list --query [].name
    • Filters output to only show Key Vault names

List Certificates in a Vault
az keyvault certificate list --vault-name KVEast3
    • Lists all certificate objects in the specified vault
az keyvault certificate list --vault-name KVEast3 --query [].name
    • Filters to show only certificate names

Create a New Certificate
az keyvault certificate create \
  --vault-name KVEast3 \
  --name Cert3 \
  --policy "$(az keyvault certificate get-default-policy)"
Parameters:
    • --vault-name: Name of the Key Vault to create the cert in
    • --name or -n: Name of the new certificate
    • --policy or -p: Certificate policy (default policy used here)
az keyvault certificate get-default-policy:
    • Returns a JSON object with the default certificate policy
    • Includes key usage, validity, export settings, etc.

Post-Creation Confirmation
    • Refresh the Certificates section in the portal under KVEast3
    • Certificate Cert3 will appear and should be in Enabled status

Certificate Details (via Portal)
    • Click on certificate (e.g., Cert3) → Current Version
    • Options available:
        ○ Download as:
            § .CER (public only)
            § .PEM / .PFX (includes private key, requires password)
    • View metadata:
        ○ Activation Date: e.g., 03/22/2023 11:47:47 AM
        ○ Expiration Date: e.g., 03/22/2024 11:57:47 AM
        ○ Region: UTC-04:00 (Atlantic Time)

Summary
    • CLI enables full lifecycle management of Key Vault certificates
    • Use the default policy unless a custom policy is needed
    • Private key downloads require password protection
    • Certificate uses include encryption, signing, and HTTPS support for apps

##  Managing Key Vault Certificates Using PowerShell

AZ-500 Study Notes: Managing Key Vault Certificates Using PowerShell

List Key Vaults
Get-AzKeyVault
    • Lists all Key Vaults in the subscription
Filter to only show vault names:
Get-AzKeyVault | Select-Object VaultName
Determine available object properties:
Get-AzKeyVault | Get-Member -MemberType Property
    • Confirms property names like VaultName (no space)

Define Certificate Policy
$Policy = New-AzKeyVaultCertificatePolicy `
  -SecretContentType 'application/x-pkcs12' `
  -SubjectName "CN=www.app1testing.com" `
  -IssuerName "Self" `
  -ValidityInMonths 12 `
  -ReuseKeyOnRenewal
Parameter Explanation:
    • -SecretContentType: Certificate format (PKCS12)
    • -SubjectName: CN (Common Name) used in the cert
    • -IssuerName: "Self" for self-signed
    • -ValidityInMonths: How long the cert is valid (e.g., 12 = 1 year)
    • -ReuseKeyOnRenewal: Reuses the same key instead of generating new one on renewal

Create a Certificate
Add-AzKeyVaultCertificate `
  -VaultName "KVEast3" `
  -Name "App2Cert" `
  -CertificatePolicy $Policy
    • Creates a certificate in vault KVEast3 named App2Cert using the $Policy defined above

Confirm Certificate Creation
Get-AzKeyVaultCertificate -VaultName "KVEast3" | Select-Object Name
    • Lists all certificates in the vault by name

Portal Confirmation
    • Go to KVEast3 → Certificates → Click Refresh
    • New cert (App2Cert) will first show as Disabled
    • After a moment, status updates to Completed

Notes
    • Self-signed certificates are not trusted by default in browsers or services unless the root CA is installed manually.
    • Certificates can be used by:
        ○ Azure App Services
        ○ Custom HTTPS domains
        ○ Digital signing / encryption


## Working with Azure Key Vault and Hardware Security Modules (HSMs)

What is a Hardware Security Module (HSM)?
    • A dedicated, tamper-resistant hardware appliance
    • Performs cryptographic operations:
        ○ Key generation
        ○ Encryption/Decryption
        ○ Digital signatures
        ○ Authentication
    • FIPS 140-2 Level 3 compliant
    • Often required for regulatory compliance:
        ○ PCI DSS
        ○ GDPR
        ○ HIPAA
