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

# Managing Az Policies

What Is Azure Policy?
    • A governance tool to enforce rules and effects on Azure resources.
    • Controls what can be deployed, how it's configured, and where it can be deployed.

Azure Policy vs RBAC
    • RBAC = Controls who can perform what actions.
    • Azure Policy = Controls what resources can be created/configured and how.
Example:
    • RBAC: "Techs can deploy VMs."
    • Policy: "Only Linux VMs of size B2ms can be deployed in West US."

Built-in and Custom Policies
    • Built-in policies: Ready-to-use for common compliance needs.
    • Custom policies: Created using a JSON definition file.

Policy Structure
    • JSON-based
    • Can use parameters (e.g., allowed locations, VM sizes)
    • Example parameter: "allowedLocations": ["westus", "eastus"]

Scope of Assignment
    • Assign policies to levels of Azure hierarchy:
        ○ Management Group → affects all subscriptions beneath it
        ○ Subscription
        ○ Resource Group
    • You can exclude specific resource groups/projects even if they're under a broader scope

Policy Effects
Effect	Description
Append	Adds settings to a resource during deployment (e.g., storage account rules)
Audit	Logs non-compliance in Activity Log
AuditIfNotExists	Logs if a related configuration is missing (e.g., encryption not enabled)
DeployIfNotExists	Checks and deploys a resource/config if not already present
Deny	Blocks resource creation if it violates policy (e.g., wrong region)


Tag Governance Example
    • Policy can add default tags if none are specified
    • Ensures consistent tagging across environment

Policy Initiatives
    • A group of policies assigned together
    • Assigned like a single policy, but includes many under the hood
    • Example initiative:
        ○ Policy 1: Enforce allowed regions
        ○ Policy 2: Require VM disk encryption
        ○ Policy 3: Require endpoint protection
    • Benefit: Simplifies management and reporting

Management Tools
    • Azure Policy can be managed through:
        ○ Azure Portal
        ○ Azure CLI
        ○ PowerShell

## Using Azure Policy to Audit Compliance

Purpose of Azure Policy Assignments
    • Enforce rules across management groups, subscriptions, or resource groups
    • Examples:
        ○ Ensure TDE is enabled for SQL
        ○ Enforce allowed regions for resource deployment
        ○ Check if disaster recovery is configured for VMs

Starting in the Portal
    1. In Azure portal, search “Policy”
    2. Opens Azure Policy blade with:
        ○ Overview
        ○ Assignments
        ○ Definitions
        ○ Compliance

Definitions Tab
    • View policy definitions and initiative definitions
    • Filter by:
        ○ Definition Type: Policy or Initiative
        ○ Initiatives are groups of related policies whether its built in or custom created
        ○  Policy are individual
        ○ Search (e.g., "encrypt", "location")

Example: Allowed Locations Policy
    1. Filter or search for "allowed locations"
    2. View the JSON policy definition
        ○ parameters: listOfAllowedLocations (string array)
        ○ effect: deny
        ○ Condition: If resource location is not in allowed list, deny deployment

Assign the Policy
Click Assign → Steps:
1. Basics (Scope and Exclusions)
    • Choose Scope:
        ○ Management Group
        ○ Subscription
        ○ Resource Group (e.g., App1)
    • Optional: Add Exclusions (e.g., exclude a project or resource)
2. Assignment Name
    • Example: Allowed locations for App1 resource group
3. Advanced (Optional)
    • Use Add Resource Selector to limit policy to specific resource types or locations
    • Skipped in this case (applies to everything in App1)
4. Parameters
    • Set the allowed region (e.g., East US)
    • Can select multiple regions if needed
5. Remediation (Optional)
    • Policy applies only to new resources
    • Existing resources require a remediation task
    • May need a managed identity for automatic remediation
6. Review + Create
    • Validate settings and click Create

Confirm Policy Assignment
    • Go to Assignments tab
    • Set Scope filter to App1 resource group
    • See assignment listed with name and compliance state

View Compliance State
    • Go to Compliance tab
    • Find policy assignment (e.g., Allowed Locations)
    • State will show as Compliant

Test Denial Enforcement
    1. Try to create a resource (e.g., Storage Account)
    2. Set:
        ○ Resource Group: App1
        ○ Region: Central US (not allowed)
    3. Azure blocks creation:
        ○ Error: “Policy validation failed”
        ○ Message: Region is not in allowedLocations

Summary
    • Azure Policy lets you enforce, audit, or auto-remediate compliance
    • Supports built-in or custom JSON policies
    • Assign to any scope (MG, sub, RG)
    • Monitor enforcement under Assignments and Compliance

## Creating and Assigning a Custom Policy

Why Use a Custom Policy?
    • Built-in policies may not cover highly specific business or technical requirements.
    • Example: Only allow Ubuntu 20.04 VMs in a specific resource group.

Steps to Create a Custom Policy (Portal)
1. Open Azure Policy
    • Search for “Policy” in the Azure Portal
    • Go to Definitions tab
2. Create New Policy Definition
    • Click Add policy definition
    • Choose Definition location: e.g., Azure subscription 1
    • Name: Ubuntu Forever
    • Category: Create new → Virtual Machines
3. Paste JSON Policy Definition
    • JSON includes:
        ○ "if": Checks if resource is VM, disk, or scale set
            § Matches:
                □ "publisher": "Canonical"
                □ "offer": "UbuntuServer"
                □ "sku": "20.04-LTS"
        ○ "then": effect = deny if condition is not met
    • Save policy

Assign the Custom Policy
1. Click Assign from the policy definition screen
    • Scope: Choose App1 resource group
    • No exclusions
    • Assignment Name: Ubuntu Forever
    • Status: Enabled
2. Click through:
    • No Advanced filters
    • No Parameters (this policy has none)
    • No Remediation tasks
    • Click Create

Test the Assignment
✅ Allowed:
    • Deploy Ubuntu 20.04 VM in App1 RG → Passes policy check
❌ Denied:
    • Deploy Windows Server or Ubuntu 18.04 in App1 RG → Fails with policy violation
    • Policy error message includes name: Ubuntu Forever
    • Clicking Policy Details shows JSON and assignment info
✅ Not Affected:
    • Create any VM in App2 RG → Passes (policy not assigned to App2)

Policy Lifecycle Notes
    • Custom policies show Type = Custom under Definitions
    • Can filter definitions by:
        ○ Search term: e.g., Ubuntu
        ○ Category: e.g., Virtual Machines

Deleting a Custom Policy
    • Must first remove all assignments
    • Otherwise deletion will fail

Summary
    • Custom policies let you define fine-grained, resource-specific controls
    • Assignment scoping ensures policy only applies where needed
    • Built-in and GitHub examples can help with writing custom policy JSON
    
     
## Assigning Az policy using cli

AZ-500 Study Notes: Assigning Azure Policy Using the Command Line

Overview
Azure Policy assignments can be created via:
    • PowerShell
    • Azure CLI
Useful for automation, scripting, and environments without GUI access.

PowerShell: Assigning a Policy
1. Set the Resource Group Variable
$rg = Get-AzResourceGroup -Name "App1"
2. Retrieve the Policy Definition
$definition = Get-AzPolicyDefinition | Where-Object {
  $_.Properties.DisplayName -eq "Audit virtual machines without disaster recovery configured"
}
3. Create the Policy Assignment
New-AzPolicyAssignment `
  -Name "VMs-DR Enabled" `
  -DisplayName "Check for VM Disaster Recovery" `
  -Scope $rg.ResourceId `
  -PolicyDefinition $definition
    • -Scope: Must be the resource ID (not just the name)
    • -PolicyDefinition: Uses the full object retrieved earlier

Confirm in Portal
    • Go to Azure Policy → Assignments
    • Set Scope to the resource group (App1)
    • Confirm policy appears (e.g., Check for VM Disaster Recovery)

Azure CLI: Assigning a Policy
1. List All Policy Definitions by Display Name
az policy definition list --query [].displayName
2. Gather Required IDs
    • Go to the portal → Find the Policy Definition ID
    • Go to the Resource Group → Copy its Resource ID
3. Create the Assignment via CLI
az policy assignment create \
  --name "UbuntuAssignment1" \
  --policy "/subscriptions/<sub-id>/providers/Microsoft.Authorization/policyDefinitions/<policy-id>" \
  --scope "/subscriptions/<sub-id>/resourceGroups/App1"
Parameters:
    • --name: Unique name for the assignment
    • --policy: Full resource path to the policy definition
    • --scope: Full resource path to the assignment scope (e.g., RG)

Confirm CLI Assignment in Portal
    • Azure Policy → Assignments
    • Set Scope to App1
    • Look for UbuntuAssignment1 listed

Notes
    • Both PowerShell and CLI require:
        ○ Policy Definition ID
        ○ Scope Resource ID
    • Portal is helpful for copying those values directly
    • Assignments created this way are active immediately

## Managing policy initiatives

What Is a Policy Initiative?
    • A grouping of related policy definitions
    • Assigned as a single unit for streamlined governance
    • Useful for applying multiple policies at once for:
        ○ Regulatory compliance (e.g., PCI-DSS, NIST SP 800-171)
        ○ Organizational standards (e.g., web app security settings)

Viewing Built-in Initiatives
    1. Go to Azure Policy
    2. Navigate to Definitions
    3. In Definition type dropdown → Select Initiative
    4. Examples:
        ○ PCI v3.2.1:2018
        ○ NIST SP 800-171 Rev.2

Assigning a Built-in Policy Initiative (e.g., PCI DSS)
1. Select Initiative
    • Click on PCI v3.2.1:2018
    • Click Assign
2. Define Scope
    • Choose:
        ○ Subscription
        ○ Resource Group (e.g., App1)
    • Optional: Add Exclusions
3. Advanced Options (optional)
    • Narrow assignment to:
        ○ Specific resource types
        ○ Specific locations
4. Parameters
    • Provide required values for any parameters
    • Some built-in initiatives prompt for multiple inputs
5. Remediation (optional)
    • Enable remediation tasks to fix existing non-compliant resources
    • May require managed identity
6. Non-Compliance Messages (optional)
    • Add guidance to help admins fix non-compliant resources
7. Review and Create
    • Click Create
    • Confirm success in Assignments view (scope = App1)

Creating a Custom Initiative
1. Go to Definitions → Click Add Initiative Definition
    • Scope: Choose Subscription or Management Group
    • Name: e.g., Web App Security
    • Category: Choose existing (e.g., Security Center) or create new
2. Add Policy Definitions
    • Click Add policy definitions
    • Filter (e.g., App Service)
    • Select relevant policies, such as:
        ○ Require HTTPS for App Services
        ○ Disable public access to App Services
        ○ Enforce TLS 1.2
        ○ Enable Defender for App Services
3. (Optional) Organize Policy Groups
    • Group related policies for easier visibility
4. Skip Parameters (if none needed)
    • Or define default values for parameterized policies
5. Create the Initiative

Assigning a Custom Initiative
    • Either click Assign from the success page
    • Or go to Assignments tab → Click Assign
    • Scope: e.g., Subscription
    • Review and Create

Viewing and Validating Assignment
    • Go to Assignments
    • Scope: Filter to Subscription or RG (e.g., App1)
    • See initiative listed (e.g., Web App Security)
    • Use Compliance tab to check evaluation status (may take time)

Notes
    • Initiatives reduce management overhead
    • Required for implementing regulatory frameworks
    • Useful for applying organization-specific bundles of policies

# EnableResourceLocking

## Azure Resource Locks

AZ-500 Study Notes: Azure Resource Locks

What Are Azure Resource Locks?
    • A way to protect resources from accidental changes or deletion
    • Can be applied at three levels:
        ○ Subscription
        ○ Resource Group
        ○ Individual Resource
    • Override RBAC permissions: even users with Owner or Contributor cannot perform restricted actions if a lock is in place

Why Use Resource Locks?
    • To prevent accidental deletion or unwanted modification of critical infrastructure
    • Useful in production environments, compliance zones, or during audits
    • Helps enforce governance even if roles allow destructive changes

Lock Types
    1. ReadOnly
        ○ Users can read the resource
        ○ Users cannot update or delete
        ○ Similar to RBAC Reader, but more restrictive:
            § On a storage account, prevents listing keys
            § No configuration changes allowed
    2. CanNotDelete
        ○ Users can read and modify
        ○ Cannot delete the resource
        ○ Example: You can still write to or update a VM, but you cannot delete the VM

Scope and Inheritance
    • Locks follow the Azure resource hierarchy
        ○ Lock at subscription → applies to all resource groups and resources under it
        ○ Lock at resource group → applies to all resources within it
    • New resources inherit lock status from parent
    • Most restrictive lock takes precedence in case of multiple locks across the hierarchy

Control Plane vs. Data Plane
Plane	Description	Affected by Lock
Control Plane	Resource configuration and lifecycle (e.g., VM settings, storage account deletion)	✅ Yes
Data Plane	Actual resource data operations (e.g., writing a blob, querying SQL, RDP to VM)	❌ No
    • Locks apply only to the control plane
    • Example: Locking a storage account does not prevent blob deletion within it

Behavior Examples
    • A CanNotDelete lock on a storage account:
        ○ Prevents deletion of the account itself
        ○ Does not stop users from deleting blobs or files inside
    • A ReadOnly lock on a VM:
        ○ Prevents resizing, reconfiguration, or deletion
        ○ Still allows reading properties

Additional Details for AZ-500
    • Locks apply immediately and persist until explicitly removed
    • You must remove a lock to delete the locked resource
    • Can be managed via:
        ○ Azure portal
        ○ ARM templates
        ○ Azure Policy (indirectly, through enforcement models)
    • Locking is an example of governance enforcement, along with:
        ○ Azure Policy
        ○ RBAC
        ○ Blueprints

> 
## Managing Azure Resource Locks Using the Portal

AZ-500 Study Notes: Managing Azure Resource Locks Using the Portal

Purpose of Resource Locks
    • Prevent accidental modification or deletion of Azure resources.
    • Applied at Subscription, Resource Group, or Individual Resource levels.
    • Overrides user RBAC permissions (e.g., Contributor role) for delete or modify actions.
Lock Types
    • Read-only: Prevents changes to resource configuration. Still allows data access in some cases but restricts control plane actions.
    • Delete: Allows changes but prevents deletion of the resource.
Hierarchical Application
    • Locks can be applied at:
        ○ Management Group level (No lock option visible in portal)
        ○ Subscription level (Resource locks available under Settings)
        ○ Resource Group level (Locks appear as "Locks" in left menu)
        ○ Individual Resource level (e.g., Storage Account)
    • Locks inherit downwards:
        ○ A lock at Subscription level applies to all child Resource Groups and resources.
        ○ New resources created under a locked scope inherit the lock.
    • Most restrictive lock wins if multiple locks exist at different levels.
Portal Navigation and Actions
At Subscription Level
    1. Navigate to Subscriptions.
    2. Choose subscription (e.g., Azure subscription 1).
    3. Under Settings, click Resource locks.
    4. Click Add to create a new lock.
    5. Enter:
        ○ Lock name: (e.g., SubscriptionLock1)
        ○ Lock type: Read-only or Delete
        ○ Optional: Add a Note
    6. Click OK.
At Resource Group Level
    1. Navigate to Resource groups.
    2. Select a group (e.g., App1).
    3. Under Settings, click Locks.
    4. Existing locks are displayed (including inherited locks).
    5. Click Refresh to update the view.
At Resource Level
    1. Navigate to All resources.
    2. Select a resource (e.g., a Storage Account).
    3. Under Settings, click Locks.
    4. View inherited or local locks.
Effect of Read-only Lock Example
    • On a Storage Account:
        ○ Cannot access Access Keys (control-plane action blocked).
        ○ Cannot change Networking settings (e.g., disable public access).
        ○ Portal displays error: "Failed to save firewall and virtual network settings" due to locked scope.
Removing Locks
    • You must remove a lock at the level it was applied.
    • E.g., a lock created at the Subscription cannot be deleted from a Resource Group or Resource level view.
    • Navigate to Azure subscription 1 > Resource locks, then click Delete.
Key Notes
    • Locks affect control plane only (not data plane):
        ○ E.g., Cannot delete Storage Account but can delete blobs inside.
    • Ensure to refresh portal views after deleting locks.
    • Locking provides additional governance alongside RBAC and Policy.

Best Practices for AZ-500
    • Use locks in production or audit-sensitive environments.
    • Always document lock types and purposes (use Notes field).
    • Combine locks with Azure Policy and Blueprints for strong governance.
    • Understand lock inheritance and evaluate where to apply them for maximum effectiveness.

## Managing Azure Resource Locks Using the CLI


AZ-500 Study Notes: Managing Azure Resource Locks Using the CLI

🔹 Purpose of Resource Locks via CLI
    • Prevents accidental modification or deletion of resources.
    • Enforced at the control plane level (not data plane).
    • Overrides RBAC roles like Contributor for delete/modify.
    • Not a true security mechanism — anyone with enough privilege can remove the lock.

🔹 Lock Types
    • CanNotDelete: Prevents deletion, allows modification.
    • ReadOnly: Prevents both deletion and modification.

🔹 Hierarchical Scope Levels (Same as portal)
    • az account lock → Subscription
    • az group lock → Resource Group
    • az resource lock → Individual Resource
💡 Locks inherit downward; most restrictive lock applies when multiple exist.

🔹 Creating Locks Using CLI
1. At Subscription Level
az account lock create --name "Cannot delete subscription" --lock-type CanNotDelete
    • Applies to all child groups and resources.
    • Confirm with:
az account lock list
    • In portal: Go to Subscription > Resource Locks to validate.
    • Must manually click Refresh to see changes.

2. At Resource Group Level
az group lock create --lock-type ReadOnly -n NoModify -g App1
    • Blocks modification at group scope.
    • Confirm with:
az account lock list
    • Can also use:
az group lock list -g App1

3. At Resource Level (e.g., Storage Account)
az resource lock create \
  --lock-type ReadOnly \
  --name NoModify \
  --resource eastyhz1 \
  --resource-type Microsoft.Storage/storageAccounts \
  --resource-group App1
    • Required: --resource, --resource-type, and --resource-group
    • Will show up in:
az account lock list

🔹 Viewing Lock Details
Show one specific lock
az account lock show --name "Cannot delete subscription"

🔹 Attempting a Delete (and Failure Scenario)
    • Try to delete a resource under a locked scope (e.g., Application Insights).
    • Portal will allow you to go through the delete dialog.
    • No visible error, but Notification bell will report:
❌ “Failed – Scope is locked”

🔹 Removing Locks Using CLI
    • Subscription:
az account lock delete --name "Cannot delete subscription"
    • Resource Group:
az group lock delete --name "NoModify" --resource-group App1
    • Individual Resource:
az resource lock delete \
  --name "NoModify" \
  --resource-group App1 \
  --resource-type Microsoft.Storage/storageAccounts \
  --resource eastyhz1
🟡 Portal may not reflect lock removal until Refresh is clicked.

🔹 Important Notes for AZ-500
    • Resource locks:
        ○ Affect control plane only.
        ○ Do not block data operations (e.g., deleting blobs inside a locked Storage Account).
    • Lock behavior may lag in the portal — always validate with Refresh.
    • CLI is preferred for bulk/automated lock management.

## Managing Azure Resource Locks Using PowerShell


AZ-500 Study Notes: Managing Azure Resource Locks Using PowerShell

🔹 Overview
    • Purpose: Prevent accidental modification or deletion of resources.
    • Not a true security mechanism:
        ○ Users with appropriate RBAC roles (e.g., Owner) can remove locks.
        ○ Locks apply to control plane, not data plane.
    • Best used as part of governance (not standalone security).

🔹 Common PowerShell Cmdlets
Get-Command *lock* -Type Cmdlet
Returns core cmdlets:
    • Get-AzResourceLock
    • New-AzResourceLock
    • Set-AzResourceLock
    • Remove-AzResourceLock

🔹 View Existing Locks
Get-AzResourceLock
    • Lists all locks in current context (subscription, resource group, etc.)
    • Narrow down scope:
Get-AzResourceLock -ResourceGroupName "App1"

🔹 Create Lock (Resource Group Level)
New-AzResourceLock -LockName "NoModify" -LockLevel ReadOnly -ResourceGroupName "App1" -Force
    • LockLevel: ReadOnly or CanNotDelete
    • -Force: Suppresses confirmation prompt
💡 PowerShell will prompt without -Force — useful to suppress in scripts

🔹 Validate Lock
Get-AzResourceLock
    • Confirms lock exists:
        ○ Name: NoModify
        ○ LockLevel: ReadOnly
        ○ Scope: Resource Group App1
🟡 Portal may lag — always click Refresh after applying a lock.

🔹 Modify Existing Lock
Set-AzResourceLock
    • Example use:
        ○ Add/update lock notes
        ○ Change lock type from ReadOnly → CanNotDelete

🔹 Remove Lock
Remove-AzResourceLock -ResourceGroupName "App1" -Name "NoModify" -Force
    • -Force: Skips confirmation
✅ Returns True on success

🔹 Final Lock Check
Get-AzResourceLock
    • Confirms all locks are cleared.

🔹 Portal View (Optional)
    • Resource group → Locks → "NoModify"
    • Lock visible after Refresh
    • Options:
        ○ Edit (change type or add notes)
        ○ Delete

🔹 Summary Notes for AZ-500
    • Locks apply at:
        ○ Subscription
        ○ Resource Group
        ○ Resource level
    • Inheritance flows downward
    • Most restrictive lock wins (if conflicts exist)
    • Locks override RBAC only temporarily — can be removed by privileged users
    • Best practice: use with Azure Policy or Blueprints for full governance


## Enabling Resource Locking with Templates


AZ-500 Study Notes: Enabling Azure Resource Locks Using ARM Templates

Overview
    • ARM templates automate deployment of Azure resources.
    • Can also apply resource locks during deployment.
    • Useful for preventing accidental deletion or modification.
    • Lock applies at control plane, not data plane.
    • Not a true security mechanism — users with RBAC can remove locks.

Template Name
    • Create a resourceGroup, apply a lock and RBAC
    • Found at: learn.microsoft.com → Code Samples
    • Filters used: Azure Resource Manager, ARM, JSON
    • Search: lock

What the Template Does
    • Creates a resource group
    • Applies a CanNotDelete lock to it
    • Assigns the Contributor role to an Azure AD principal (Object ID)

Deploy via Azure Portal
    1. Click Deploy to Azure
    2. Fill:
        ○ Subscription
        ○ Region
        ○ rgName → Resource group name (e.g., RgLockTest)
        ○ rgLocation → Azure region (e.g., eastus)
        ○ principalId → Azure AD Object ID (copied from user page)
        ○ roleDefinitionId → Contributor role ID (auto-filled)
        ○ roleAssignmentName → Optional, auto-generated
    3. Click Review + Create → then Create

Editing the ARM Template
    1. Click Edit template at the top of the deployment screen
    2. Parameters:
        ○ rgName (string)
        ○ rgLocation (string)
        ○ principalId (string)
        ○ roleDefinitionId (string, default is Contributor ID)
        ○ roleAssignmentName (generated using guid() functions)
    3. Resources created:
        ○ Resource Group: Microsoft.Resources/resourceGroups
        ○ Lock: Microsoft.Authorization/locks
            § name: DontDelete
            § level: CanNotDelete
            § notes: "Prevent deletion of the resourceGroup"
        ○ RBAC Assignment: Microsoft.Authorization/roleAssignments

Post-Deployment Validation
    1. Go to Resource groups > RgLockTest
    2. Under Access Control (IAM) → Role Assignments:
        ○ Filter for username (e.g., Codey Blackwell)
        ○ Confirm Contributor role is assigned
    3. Under Locks:
        ○ Confirm lock name: DontDelete
        ○ Lock type: Delete
    4. Under Overview:
        ○ Location confirms deployment region (e.g., East US)
    5. Remember to click Refresh — UI may take time to reflect lock changes

Notes on PrincipalId
    • The PrincipalId is the Azure AD user's Object ID
    • Found under:
        ○ Azure AD → Users → Select user → Object ID under "Basic Info"

Best Practices (AZ-500)
    • Use resource locks in ARM templates to enforce governance
    • Combine with role assignments for scoped access control
    • Document purpose of each lock via the notes field
    • Don’t rely on locks as security — RBAC trumps it
    • Validate deployments post-creation (locks + role assignments)
    • Use ARM templates when deploying at scale or automating infrastructure

# Securing Az with Defender & Sentinel

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


## Managing Microsoft Defender for Cloud for Databases


Managing Microsoft Defender for Cloud for Databases (AZ-500 Focused)

🎯 Purpose
    • Provide threat protection and vulnerability assessment for Azure and non-Azure databases.
    • Detects suspicious activity like:
        ○ SQL injection
        ○ Brute-force login attempts
        ○ Unauthorized data access
    • Scans configuration for security misconfigurations, compliance gaps, and missing best practices
    • Integrates with AWS, GCP, on-prem databases using Azure Arc

🔧 Enabling Defender for Databases
    1. Go to Microsoft Defender for Cloud → Environment Settings
    2. Choose Management Group or your Azure Subscription
    3. Click Defender plans
    4. Scroll to Database section
    5. Toggle Defender ON, then click Select types:
        ○ Azure SQL Database ✅
        ○ SQL servers on machines (on-prem or IaaS)
        ○ Azure Cosmos DB
        ○ Open-source relational DBs (e.g., MySQL, PostgreSQL)
    6. Save configuration

✉️ Alerts & Automation
    • Email Notifications:
        ○ Owner role notified by default
        ○ Can add other roles (e.g., Contributor) or custom emails
    • Workflow Automation:
        ○ Define triggers (e.g., High-severity alert)
        ○ Run Logic Apps to:
            § Quarantine resources
            § Auto-remediate issues
            § Send alerts to SIEM or ticketing systems

🏗 Creating a Secure SQL Database (With Defender)
    1. Portal → Create Resource → Azure SQL → Single Database
    2. Configure:
        ○ Resource group
        ○ Database name (e.g., app1sqldb1)
        ○ New/existing SQL Server
    3. Authentication:
        ○ SQL Authentication (Username + Password)
        ○ Optional: Azure AD integration
    4. Networking:
        ○ Use Private endpoint
        ○ Avoid public IP exposure
        ○ Assign to VNet/Subnet
    5. Security Tab:
        ○ Toggle Microsoft Defender for SQL → "Start Free Trial" or "Enable"
    6. Proceed with:
        ○ Sample data
        ○ Tagging
        ○ Review + Create

🧪 Post-Deployment Monitoring
    • Go to SQL Database → Microsoft Defender for Cloud
    • Under Security, view:
        ○ Recommendations (e.g., restrict public access)
        ○ Severity (High, Medium, Low)
        ○ Tactics/Techniques (e.g., Initial Access)
    • Use:
        ○ Quick Fix (auto sets allowBlobPublicAccess: false)
        ○ Assign Owner for follow-up
        ○ Exempt (optional, if justified)
    • Open View Policy Definition for granular control
    • Use Deny Policy Effect to prevent insecure deployments

🔍 Recommendation Examples
    • "Public access should be disabled"
    • "Use private endpoints"
    • "Enable advanced threat protection"
    • "Encrypt data at rest and in transit"
    • "Install vulnerability assessment extensions"

🧠 Additional Details
    • Defender auto-assesses new + existing databases
    • Use View all recommendations to see tenant-wide security posture
    • Supports compliance monitoring (e.g., PCI DSS, ISO 27001, SOC TSP)
    • Defender checks apply regardless of deployment method (manual, ARM, Terraform)

✅ Key AZ-500 Concepts
    • Microsoft Defender for SQL is part of Defender for Cloud
    • Protects both PaaS (Azure SQL DB) and IaaS-hosted SQL (via Arc agent)
    • Enables threat detection, policy assignment, and remediation workflows
    • Best practice: deploy using Private endpoints, enable Defender, and assign remediation automation>


## Viewing Microsoft Cloud Vulnerability Scan Results



Viewing Microsoft Cloud Vulnerability Scan Results (via Defender for Cloud)
Purpose
    • Microsoft Defender for Cloud scans Azure, AWS, GCP, and on-premises (via Azure Arc) for:
        ○ Vulnerabilities
        ○ Misconfigurations
        ○ Indicators of compromise (IoC)
Access Methods
    • View scan results at:
        ○ Individual resource level (e.g., VM, Storage Account)
        ○ Global view via Defender for Cloud dashboard

Resource-Level Scan (Example: Virtual Machine)
    • Navigate to VM > Defender for Cloud
        ○ View individual recommendations
        ○ Severity levels (High, Medium, Low)
        ○ Specific findings like “Install endpoint protection,” “Encrypt disks”

Global Security Posture View
    • From Portal: Search Defender, open Microsoft Defender for Cloud
    • Overview:
        ○ Unified view of security recommendations across Azure and linked AWS/GCP accounts
        ○ Security Score
        ○ Assessed Resources Count

Environment Settings
    • View connected environments:
        ○ Azure subscriptions
        ○ External accounts (AWS/GCP)
    • Inventory includes EC2 instances, on-prem VMs, Azure resources

Inventory View
    • Filter by:
        ○ Cloud provider (Azure, AWS, GCP)
        ○ Resource Type (e.g., EC2, VM, Storage)
    • Drill down for:
        ○ Installed applications
        ○ Security recommendations
        ○ Affected resources
    • Export to CSV for external analysis (e.g., Excel filtering by resource type)

Regulatory Compliance
    • Microsoft Cloud Security Benchmark
    • Other Standards:
        ○ PCI DSS 3.2.1
        ○ ISO 27001
        ○ SOC TSP
    • View and download compliance reports:
        ○ Azure Shared Responsibility Matrix
        ○ Attestation of Compliance PDFs

Key Actions
    • Click Recommendations to view/fix misconfigurations
    • Use Audit Reports for compliance verification
    • Monitor AWS/GCP VMs like native Azure VMs
    • Download and manipulate CSV reports for documentation or audits

## Security Information and Event Management (SIEM) and Azure Sentinel

SIEM and Microsoft Sentinel (AZ-500 Study Notes)
SIEM Overview
    • SIEM = Security Information and Event Management
    • Purpose: Centralized threat detection, analysis, and response
    • Consolidates and correlates logs from multiple sources to detect anomalies, threats, and breaches
    • Core Functions:
        ○ Event aggregation (collects from many systems)
        ○ Correlation of events (identifies patterns)
        ○ Real-time alerting and dashboards
        ○ Forensic investigation support
        ○ Compliance reporting

SOAR Overview
    • SOAR = Security Orchestration, Automation, and Response
    • Extends SIEM with automated remediation and workflow orchestration
    • Can:
        ○ Run playbooks in response to alerts
        ○ Integrate with ticketing, email, or IP blocking systems
        ○ Allow human-in-the-loop or full automation

Microsoft Sentinel
    • Cloud-native SIEM + SOAR in Azure
    • Designed to analyze security data at scale with built-in AI/ML
    • Integrates with:
        ○ Microsoft Defender for Cloud
        ○ Microsoft 365 Defender
        ○ Azure AD
        ○ 3rd-party data sources (e.g., AWS, Barracuda, Cisco, Fortinet)

Core Components
1. Log Analytics Workspace
    • Foundation for Sentinel
    • All ingested data is stored here
    • Supports KQL (Kusto Query Language) for queries
2. Data Connectors
    • Prebuilt integrations for data ingestion
    • Examples:
        ○ Microsoft services: Azure AD, Defender, Office 365
        ○ 3rd-party: AWS CloudTrail, Palo Alto, Cisco ASA, Fortinet
        ○ Syslog: Generic log source for Linux/UNIX
    • Custom connectors supported via REST API or Logic Apps
3. Analytics Rules
    • Use built-in or custom rules to generate incidents from ingested data
    • Detect:
        ○ Unusual login behavior
        ○ Port scanning
        ○ Lateral movement
        ○ Exfiltration attempts
4. Incidents
    • Result of triggered analytics rules
    • Contain:
        ○ Timeline of related events
        ○ Entities involved (IP, user, hostname)
        ○ Severity & status (New, In Progress, Closed)
5. Workbooks
    • Dashboards for visualization
    • Customizable per scenario:
        ○ Threat hunting
        ○ Compliance reporting
        ○ SOC operations
6. Playbooks (SOAR)
    • Based on Azure Logic Apps
    • Respond automatically to incidents
    • Examples:
        ○ Disable user in Azure AD
        ○ Block IP in NSG
        ○ Send email/slack alert
        ○ Create ServiceNow ticket
7. Hunting
    • Manual threat investigation using KQL
    • Used by SOC analysts
    • Includes built-in hunting queries (MITRE ATT&CK mapped)
8. Entity Behavior Analytics (UEBA)
    • Identifies behavioral anomalies per user or host
    • Detects:
        ○ Impossible travel
        ○ Login location anomalies
        ○ Abnormal file access
9. Watchlists
    • External lists imported into Sentinel (IP blacklist, HR termination list, etc.)
    • Referenced in detection rules or queries

Use Cases
    • Ingest and correlate:
        ○ Azure VM logs, NSG flow logs
        ○ AWS CloudTrail events
        ○ Microsoft 365 login logs
    • Detect brute force, phishing, or insider threats
    • Auto-respond:
        ○ Quarantine VM
        ○ Disable account
        ○ Block IP on perimeter firewall

Integration Examples
Source	Method	Use In Sentinel
Azure AD logs	Built-in connector	Detect suspicious logins
AWS CloudTrail	Data connector + API keys	Monitor cloud activity
Linux servers	Syslog agent to Log Analytics	Monitor SSH activity, sudo, etc.
On-prem firewall	Common Event Format (CEF) agent	Ingest traffic logs, threat alerts
Defender for Endpoint	Native integration	Get device-level threats

Best Practices for AZ-500
    • Always use Log Analytics Workspace in the same region as resources
    • Enable MFA and monitor failed login attempts
    • Create custom analytics rules to suit your org
    • Use built-in templates for connectors and rules first
    • Configure Logic App-based Playbooks for SOAR
    • Use workbooks for executive dashboards
    • Regularly review incident timeline and severity
    • Enable UEBA for behavior-based detections

Microsoft Sentinel vs Other SIEMs
Feature	Microsoft Sentinel	Traditional SIEMs (e.g., Splunk)
Deployment	Fully cloud-native	On-prem or hybrid
Data ingestion	Azure-native & 3rd-party	Depends on integration effort
Scaling	Auto-scale with Azure	Manual provisioning
Pricing	Pay-as-you-go (GB ingested)	Often license-based
SOAR	Built-in (Logic Apps)	May need separate product/module

 
## Managing Azure Sentinel Connectors and Alerts


Managing Azure Sentinel Connectors and Alerts
1. Overview
    • Microsoft Sentinel must be attached to a Log Analytics workspace
    • Workspaces store ingested data, logs, incidents, alerts, and enable hunting with KQL
    • Data Connectors bring in telemetry from diverse sources
    • Alerts can trigger playbooks, notifications, or manual/automated incident response

2. Accessing Sentinel
    • Go to Azure Portal > Search: "Sentinel"
    • If not set up, create a Log Analytics Workspace
    • Attach Sentinel to it via "Add"

3. Data Connectors
    • Found under Configuration > Data connectors
    • 100+ built-in connectors for:
        ○ Azure services: AAD, Key Vault, NSG, Storage, etc.
        ○ Third-party sources: AWS, Cisco ASA, Barracuda, Fortinet, Palo Alto
        ○ On-prem devices: via Syslog, CEF (Common Event Format), REST APIs
Examples:
Connector Source	Data Types Ingested	Prerequisites
Azure Active Directory	Sign-in logs, audit logs, risky users	Azure AD diagnostic settings + proper roles (Global Admin)
Azure Storage Account	Blob read/write/delete logs	Configure diagnostic settings → Log Analytics
NSG (Network Security Group)	Flow logs	Assign Azure Policy to send diagnostics to workspace
Cisco Meraki	Firewall/Security device logs via Syslog	Configure syslog export to Log Analytics
    ⚠️ After free data ingestion quota (5GB/day as of writing), costs apply per GB, so only ingest what's needed

4. Steps to Connect a Data Source (e.g., Azure AD)
    1. Go to Sentinel > Data Connectors
    2. Click on source (e.g., Azure Active Directory)
    3. Review prerequisites (roles, diagnostics)
    4. Enable necessary logs (Sign-In, Audit, Risky Users, etc.)
    5. Apply changes → Sentinel begins ingesting logs

5. Custom Diagnostic Settings for Storage
    1. Open Azure Storage Account
    2. Go to Monitoring > Diagnostic Settings
    3. Click Add Diagnostic Setting
    4. Choose Log Analytics workspace destination
    5. Enable relevant categories (Blob logs, etc.)
    6. Save

6. NSG Logs with Azure Policy
    • Some connectors (like NSG) require Azure Policy Assignment
    • Steps:
        1. Launch Policy Wizard from connector page
        2. Assign to subscription or resource group
        3. Select Log Analytics workspace
        4. Enable remediation task
        5. Create assignment → NSG logs sent to Sentinel

7. Handling Third-Party Devices
    • E.g., Cisco Meraki
        ○ Needs Syslog configured
        ○ Sentinel provides instructions for log forwarding
        ○ Use Syslog/CEF collector VMs if needed

8. Sentinel Automation & Alerts
    • Found under Automation > Rules / Playbooks
    • Trigger response actions when:
        ○ Analytics rules fire
        ○ Specific incidents or thresholds are met
    • Actions can include:
        ○ Send email/Teams/Slack alert
        ○ Call Logic App playbook
        ○ Assign incident owner (e.g., Codey Blackwell)
        ○ Disable user or block IP

9. Hunting and Queries
    • Go to Hunting blade
    • Use KQL to:
        ○ Search for indicators of compromise (IoCs)
        ○ Investigate known campaigns (e.g., WannaCry DNS domains)
    • Select a query > Run selected query > View results

10. Best Practices
    • Regularly review connected connectors and data cost
    • Use filters to find connectors by vendor or type
    • Automate common alert responses with playbooks
    • Test queries in Hunting before creating new detection rules
    • Monitor ingestion costs post-trial and refine logs ingested
    • Review incident severity, assign owners, and triage frequently

AZ-500 Exam Tips
    • Know how to connect services to Sentinel using diagnostic settings
    • Understand prerequisites for major connectors like Azure AD, NSG
    • Be able to configure alert automation using Logic Apps
    • Be familiar with role requirements: Global Admin, Security Admin
    • Understand how to manage ingestion from on-prem (Syslog/CEF) and third-party


## Threat Modeling with the Microsoft Threat Modeling Tool


Threat Modeling with the Microsoft Threat Modeling Tool
1. Purpose
    • Helps IT admins, security engineers, developers visualize and secure app/data flows
    • Used to identify, analyze, and mitigate threats early in the development lifecycle
    • Free tool from Microsoft, designed for Windows

2. Setup
    • Download from Microsoft’s official page
    • Requirements: Windows 10 Anniversary Update+, .NET 4.7.1+
    • Install via one-click setup
    • Launch the app and agree to license terms

3. Core Features
    • Supports Azure-specific templates (e.g., Azure Storage, Web Apps)
    • Drag-and-drop UI with components like:
        ○ Azure services (Storage, Web Apps, SQL)
        ○ Clients (Web browser, Mobile client, IoT)
        ○ Data flows (e.g., HTTP requests)

4. Workflow
Step-by-step:
    1. Open a template or start a new model
        ○ Example: "Azure Cloud Services" template
    2. Add components from the Stencils pane:
        ○ E.g., Azure Storage + Web Application + Request
    3. Configure Properties:
        ○ Azure Storage: type = Blob, enforce HTTPS
        ○ Web App: type = MVC or Web Forms
        ○ Data Flow: customize method (GET/POST), transport protocol
    4. Click View > Analysis View to run threat analysis
        ○ Tool lists identified threats automatically
        ○ Example threat: Unauthorized access to Azure Storage

5. Threat Analysis Output
Each threat includes:
Field	Description
Threat Name	E.g., Unauthorized access due to weak controls
Description	Explains how attacker might exploit the flaw
Mitigations	E.g., Use SAS (Shared Access Signature), enforce HTTPS, set RBAC properly

6. Model Management
    • Save models (e.g., SimpleAzureWebApp.tms)
    • Switch between Design View and Analysis View
    • Use File > Save or File > Export for documentation or audit trails

7. Advanced Modeling
    • Add more entities: Web Browser, Mobile Client, IoT Device, CRM
    • Mobile Client Technologies include:
        ○ Android, iOS, CRM Outlook Client, Dynamics Mobile
    • Define relationships and trust boundaries visually

8. Security Use Cases
Use Case	How Tool Helps
Azure Web App accessing Storage	Visualize flow, enforce HTTPS, restrict blob access
Client-server authentication flows	Model session tokens, credential storage, authorization gaps
IoT integration with cloud services	Analyze data integrity and communication exposure
Web APIs & third-party service usage	Spot over-permissive calls or weak auth flows

9. Benefits for Azure/AZ-500
    • Visualize attack surface of Azure-hosted apps/services
    • Identify issues before deployment
    • Understand use of mitigations like:
        ○ Shared Access Signatures
        ○ Role-Based Access Control (RBAC)
        ○ Network Security Group (NSG) limitations
    • Prepares for secure design questions on AZ-500

10. Best Practices
    • Use pre-built templates for cloud services when available
    • Always enforce HTTPS and proper access control in diagrams
    • Run analysis after all flows and assets are mapped
    • Document and export threat models for audit or review
    • Incorporate threat modeling into DevSecOps pipelines

## Managing Azure VM Updates



Managing Azure VM Updates
1. Why It Matters
    • Ensures critical security patches are applied
    • Prevents exploitation from unpatched OS vulnerabilities
    • Must balance security with stability/testing

2. Two Ways to Manage Updates
Method	Description
Per-VM Manual	Through individual VM settings in Azure portal
Automation Account	Centralized update management via Log Analytics & Update Management

3. Manual Updates (Per VM)
Steps:
    1. Go to Virtual machines in Azure Portal
    2. Select a VM (Linux or Windows)
    3. In left nav: under Operations, click Updates
    4. Click Check for updates (if needed)
Options:
    • One-time update: Apply now
    • Classifications: Filter by Security, Critical, etc.
    • View update list by:
        ○ Name/version
        ○ Category
        ○ Count (e.g., 86 total updates, 60 critical)
    • Reboot options:
        ○ Reboot if required
        ○ Never reboot
        ○ Always reboot
    • Maintenance window: Duration (in minutes) Azure has to apply updates
Scheduling:
    • You can also click Schedule update for recurring deployments

4. Automation Account + Update Management (Recommended at scale)
4.1. Create Automation Account
    1. Azure Portal → search Automation Account → Create
    2. Fill in:
        ○ Name (e.g., automation1)
        ○ Region (e.g., East US)
        ○ Identity: System-assigned
        ○ Public access allowed
        ○ No Tags (optional)
    3. Click Create → Go to resource

4.2. Enable Update Management
    • In the Automation Account:
        1. Click Update Management in left nav
        2. Link to a Log Analytics Workspace
            § Can use existing or create new
        3. Click Enable
        4. After enabling, refresh the screen

4.3. Add Virtual Machines
    • Click Add Azure VMs
    • Select VMs to monitor (Windows/Linux)
    • Click Enable
    Can also add non-Azure machines via Azure ARC

5. Schedule Update Deployment
After VMs are added:
    • Click Schedule update deployment
    • Options include:
        ○ Update classification (Security, Critical, etc.)
        ○ Include/Exclude specific updates (e.g., by KB ID)
        ○ Reboot settings
        ○ Maintenance window
        ○ Recurring schedule

6. Benefits of Using Automation Account
Feature	Benefit
Centralized control	Manage updates for 100s of VMs from one place
Reporting	See compliance and missing updates in Log Analytics
Supports hybrid environments	Works for Azure VMs + on-premises via ARC
Integration with Security	Helps meet compliance/audit standards (e.g., PCI, NIST)

7. Best Practices
    • Always test updates in dev/staging before prod
    • Schedule updates during maintenance windows
    • Set "Reboot if required" for safer automation
    • Monitor compliance using Log Analytics queries

8. AZ-500 Relevance
    • Understanding Update Management is key to:
        ○ Maintaining secure posture
        ○ Managing hybrid cloud security
        ○ Automating remediation as part of SOAR
    • May be tested on:
        ○ VM update compliance
        ○ Automation Account setup
        ○ Linking Log Analytics

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
  
 # Ensuring buisness continuity 

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

# Ensuring Business Continuity
## Azure Backup Solutions 


Azure Backup Solutions (AZ-500 Focus)
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
 

##  Backing Up Azure Virtual Machines



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

# Review Lab type shit

## Managing User Permissions to Azure Resources

1. Managing User Permissions to Azure Resources
Objective:
    • Implement least-privilege access by grouping users based on attributes (like city = Toronto) and assigning appropriate roles at the resource level.
    • Ensure dynamic scaling of permissions as users meet group criteria.
Why It Matters:
    • Prevents over-provisioning of access
    • Supports dynamic environments (e.g., hiring in Toronto auto-adds users to the right group with right access)
    • Complies with Zero Trust principle of role-based access controls (RBAC)
Portal Steps:
    1. Create Dynamic Group:
        ○ Azure Active Directory > Groups > + New group
        ○ Group type: Security
        ○ Group name: Toronto_Users
        ○ Membership type: Dynamic User
        ○ Add owner: Abu Adachi
        ○ Add dynamic rule: Property = city, Operator = equals, Value = Toronto
    2. Add User:
        ○ Azure AD > Users > + New user
        ○ Set Name: Julio Chavez, UPN: jchavez@yourdomain.com
        ○ After creation, open profile → Edit properties → Set City = Toronto
    3. Assign Role to Group:
        ○ Resource Group > App1 > IAM > Add Role Assignment
        ○ Role: Storage Blob Data Reader
        ○ Assign to: User, group, or service principal → Select Toronto_Users
PowerShell:
# Create user
New-AzADUser -DisplayName "Julio Chavez" -UserPrincipalName "jchavez@yourdomain.com" \
  -MailNickname "jchavez" -PasswordProfile @{Password="Password123!"; ForceChangePasswordNextLogin=$true} \
  -AccountEnabled $true -UsageLocation "CA"
# Set user city
Update-MgUser -UserId "jchavez@yourdomain.com" -City "Toronto"
# Create dynamic group
$rule = '(user.city -eq "Toronto")'
New-MgGroup -DisplayName "Toronto_Users" -MailEnabled:$false -MailNickname "torontousers" \
  -SecurityEnabled:$true -GroupTypes @("DynamicMembership") \
  -MembershipRule $rule -MembershipRuleProcessingState "On"
# Assign role
$group = Get-AzADGroup -DisplayName "Toronto_Users"
New-AzRoleAssignment -ObjectId $group.Id -RoleDefinitionName "Storage Blob Data Reader" -ResourceGroupName "App1"
Azure CLI:
az ad user create --display-name "Julio Chavez" \
  --user-principal-name jchavez@yourdomain.com \
  --password "Password123!" --force-change-password-next-login true
az rest --method patch --uri "https://graph.microsoft.com/v1.0/users/jchavez@yourdomain.com" \
  --headers "Content-Type=application/json" \
  --body '{"city":"Toronto"}'
az ad group create --display-name "Toronto_Users" --mail-nickname "torontousers"
az rest --method patch --uri "https://graph.microsoft.com/v1.0/groups/<groupId>" \
  --headers "Content-Type=application/json" \
  --body '{ "groupTypes":["DynamicMembership"], "membershipRuleProcessingState":"On", "membershipRule":"(user.city -eq \"Toronto\")" }'
az role assignment create --assignee <group-object-id> --role "Storage Blob Data Reader" --resource-group App1

## Defining Custom RBAC Roles


    • Defining Custom RBAC Roles
Objective:
Create and assign a custom RBAC role that provides:
        ○ Full VM management permissions
        ○ Read-only access to Blob storage
        ○ Scope: Resource group App1


Security Context / Why We Do This:
        ○ Custom roles offer granular control when built-in roles don’t match the exact operational needs.
        ○ Helps meet least privilege and compliance mandates.
    • Limits lateral movement potential by restricting scope to App1 only.

Key Concepts from Video:
    • Combine multiple actions into a single role: VM management + Blob read
    • Ensure the assignable scope is set to avoid global role misuse
    • Roles must follow JSON schema (or portal equivalent)

Portal Steps:
    1. Go to Subscriptions > Choose subscription > Access control (IAM) > + Add > Add custom role
        ○ Name: Custom VM Management
        ○ Start from scratch
        ○ Permissions:
            § Add: Microsoft.Compute/*
            § Add: Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read
        ○ Assignable scope: /subscriptions/<subId>/resourceGroups/App1
        ○ Click Review + create
    2. Assign Role to User
        ○ Go to Resource groups > App1 > Access control (IAM)
        ○ Click + Add > Add role assignment
        ○ Filter by: Custom VM Management
        ○ Assign to: Abu

PowerShell:
# Create custom role definition
$customRole = @{
  Name = "Custom VM Management"
  Id = (New-Guid).Guid
  IsCustom = $true
  Description = "VM admin and blob read"
  Actions = @(
    "Microsoft.Compute/*",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
  )
  NotActions = @()
  DataActions = @()
  NotDataActions = @()
  AssignableScopes = @("/subscriptions/<subId>/resourceGroups/App1")
}
$roleJson = $customRole | ConvertTo-Json -Depth 10
$rolePath = "./customRole.json"
$roleJson | Out-File $rolePath
New-AzRoleDefinition -InputFile $rolePath
# Assign role
$user = Get-AzADUser -DisplayName "Abu"
New-AzRoleAssignment -ObjectId $user.Id -RoleDefinitionName "Custom VM Management" -Scope "/subscriptions/<subId>/resourceGroups/App1"

Azure CLI:
# Create custom role definition
cat <<EOF > custom-role.json
{
  "Name": "Custom VM Management",
  "IsCustom": true,
  "Description": "VM admin and blob read",
  "Actions": [
    "Microsoft.Compute/*",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
  ],
  "AssignableScopes": ["/subscriptions/<subId>/resourceGroups/App1"]
}
EOF
az role definition create --role-definition custom-role.json
# Assign role
userId=$(az ad user show --id abu@yourdomain.com --query id -o tsv)
az role assignment create \
  --assignee $userId \
  --role "Custom VM Management" \
  --scope "/subscriptions/<subId>/resourceGroups/App1"

##  Configuring Conditional Access Policies


3. Configuring Conditional Access Policies
Objective:
    • Protect cloud applications using identity-based conditions and contextual signals
    • Create policy for app "Mobile Xpense" requiring MFA, Android platform, from trusted subnet
Why It Matters:
    • Prevents unauthorized access from unknown devices/locations
    • Combats credential theft via phishing by enforcing MFA
    • Meets compliance requirements (e.g., location-aware access)
Security Context / Why We Do This:
    • Conditional Access enforces Zero Trust principles: never trust, always verify.
    • Ensures only compliant devices from trusted networks can access sensitive apps.
    • Combines user context, device state, and network location to control access.
    
Portal Steps:
    1. Create named location:
        ○ Azure AD > Security > Named Locations > Add IP range
        ○ Name: Headquarters Europe
        ○ IP Range: 192.168.1.0/24 → Mark as trusted
    2. Create Conditional Access Policy:
        ○ Azure AD > Security > Conditional Access > New Policy
        ○ Name: Allow Access to Mobile Xpense
        ○ Assign to: All Users
        ○ Cloud App: Mobile Xpense
        ○ Conditions:
            § Device Platform: Android
            § Locations: Include Headquarters Europe
        ○ Access Control: Grant access → Require MFA
        ○ Enable Policy: On
PowerShell:
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
New-MgConditionalAccessNamedLocation -DisplayName "Headquarters Europe" `
  -IpRange @{Ranges="192.168.1.0/24"; IsTrusted=$true}
New-MgConditionalAccessPolicy -DisplayName "Allow Access to Mobile Xpense" `
  -State "enabled" `
  -Conditions @{
      Users = @{Include = @("All")}
      Platforms = @{Include = @("android")}
      Locations = @{Include = @("<location-id>")}
    } `
  -GrantControls @{BuiltInControls = @("mfa")} `
  -Applications @{IncludeApplications = @("<mobile-xpense-app-id>")}
Azure CLI:
    ❌ Not available in az CLI directly. Use Microsoft Graph CLI or REST API.

## Assigning Permissions to Azure VMs

4. Assigning Permissions to Azure VMs
Objective:
    • Configure a system-assigned managed identity on a VM (WinSrv2019-2)
    • Grant it the Storage Blob Data Reader role
    • Allow the VM to securely access storage blobs in the App1 resource group

Security Context / Why We Do This:
    • Avoids use of hard-coded secrets or credentials in scripts and apps
    • Enforces least privilege via role-based access control (RBAC)
    • Enables secure service-to-service authentication within Azure
    • Managed identities are automatically rotated and protected by Azure AD

Key Concepts from Video:
    • System-assigned identity is bound to the lifecycle of the VM. When the VM is deleted, the identity is automatically removed.
    • Assigning roles to this identity enables secure access to Azure resources, like storage accounts, without embedding credentials.
    • In this scenario, the identity will be used to access blobs, which can contain app configurations, logs, or other shared data.

Portal Steps:
    1. Enable System-Assigned Identity
        ○ Go to Virtual Machines > Select WinSrv2019-2
        ○ Click Identity under the Settings section
        ○ Set System-assigned status to On and click Save
    2. Grant Storage Permissions
        ○ Navigate to the Storage Account where blob data resides
        ○ Go to Access Control (IAM) → + Add → Add role assignment
        ○ In Role, search for and select Storage Blob Data Reader
        ○ In Assign access to, choose Managed identity
        ○ Click Select members → find and select WinSrv2019-2
        ○ Click Review + assign

PowerShell:

powershell
CopyEdit
# Enable system-assigned identity
$vm = Get-AzVM -Name "WinSrv2019-2" -ResourceGroupName "App1"
$vm.Identity.Type = 'SystemAssigned'
Update-AzVM -VM $vm -ResourceGroupName "App1"
# Retrieve the identity's principal ID
$identity = (Get-AzVM -ResourceGroupName "App1" -Name "WinSrv2019-2").Identity.PrincipalId
# Assign Storage Blob Data Reader role
New-AzRoleAssignment `
  -ObjectId $identity `
  -RoleDefinitionName "Storage Blob Data Reader" `
  -Scope "/subscriptions/<subId>/resourceGroups/App1/providers/Microsoft.Storage/storageAccounts/<storageAccountName>"

Azure CLI:

bash
CopyEdit
# Enable system-assigned identity
az vm identity assign \
  --name WinSrv2019-2 \
  --resource-group App1
# Retrieve identity principal ID
principalId=$(az vm show -g App1 -n WinSrv2019-2 --query identity.principalId -o tsv)
# Assign role to identity
az role assignment create \
  --assignee $principalId \
  --role "Storage Blob Data Reader" \
  --scope "/subscriptions/<subId>/resourceGroups/App1/providers/Microsoft.Storage/storageAccounts/<storageAccountName>"


## Hardening Azure SQL Managed Instance



5. Hardening Azure SQL Managed Instance
Objective:
    • Apply foundational security controls to protect an Azure SQL Database:
        ○ Enable Transparent Data Encryption (TDE)
        ○ Turn on Microsoft Defender for Cloud
        ○ Configure daily backups with retention
        ○ Apply Dynamic Data Masking (DDM)
        ○ Restrict access via SQL firewall rules

Security Context / Why We Do This:
    • TDE encrypts data at rest, protecting against unauthorized access to underlying storage
    • Defender for SQL offers threat detection and vulnerability scanning
    • Firewall rules control who can connect to the SQL instance
    • DDM obfuscates sensitive data in query results without changing the underlying database
    • Backup policies ensure recoverability and regulatory compliance (e.g., HIPAA, ISO)

Key Concepts from Video:
    • SQL is often a critical asset—customer, financial, or health data is often stored here
    • Misconfiguration can lead to data leaks, especially when accessed from public IPs
    • Best practice: Combine platform security (TDE, firewall) with identity controls and masking
    • Defender can send alerts to Microsoft Defender for Cloud, which provides recommendations

Portal Steps:
    1. Enable Transparent Data Encryption (TDE):
        ○ Go to SQL databases > Select your DB (e.g., db1)
        ○ Under Security, click Transparent Data Encryption
        ○ Set to ON → Click Save
    2. Enable Microsoft Defender for SQL:
        ○ Go to Microsoft Defender for Cloud > Environment settings
        ○ Select the subscription > SQL servers
        ○ Enable Microsoft Defender for SQL for your server (e.g., sqlserver01)
    3. Configure Backup Retention Policy:
        ○ Navigate to SQL Server > sqlserver01 > Backups
        ○ Set Retention policy → Choose 24 hours (or as needed)
        ○ Save settings
    4. Apply Dynamic Data Masking (DDM):
        ○ Go to SQL databases > Select db1 > Security > Dynamic Data Masking
        ○ Click + Add masking rule
            § Choose sensitive column (e.g., SSN, creditCard)
            § Set masking format (e.g., default, custom string)
        ○ Click Add
    5. Restrict IP Access via Firewall Rules:
        ○ Go to SQL Server > sqlserver01 > Networking
        ○ Click + Add client IP or define range (e.g., 192.168.1.0/24)
        ○ Click Save

PowerShell:
# Enable Transparent Data Encryption
Set-AzSqlDatabaseTransparentDataEncryption `
  -ResourceGroupName "App1" `
  -ServerName "sqlserver01" `
  -DatabaseName "db1" `
  -State "Enabled"
# Enable Microsoft Defender (Threat Detection Policy)
Set-AzSqlServerThreatDetectionPolicy `
  -ResourceGroupName "App1" `
  -ServerName "sqlserver01" `
  -State Enabled
# Add firewall rule
New-AzSqlServerFirewallRule `
  -ResourceGroupName "App1" `
  -ServerName "sqlserver01" `
  -FirewallRuleName "AllowMyIP" `
  -StartIpAddress "192.168.1.1" `
  -EndIpAddress "192.168.1.1"

Azure CLI:
# Enable TDE
az sql db tde set \
  --resource-group App1 \
  --server sqlserver01 \
  --name db1 \
  --status Enabled
# Enable Defender for SQL (threat detection)
az sql server threat-policy update \
  --resource-group App1 \
  --server sqlserver01 \
  --state Enabled
# Add firewall rule
az sql server firewall-rule create \
  --resource-group App1 \
  --server sqlserver01 \
  --name AllowMyIP \
  --start-ip-address 192.168.1.1 \
  --end-ip-address 192.168.1.1
> 

##  Encrypting Azure VM Disks


7. Configuring Time-Limited Restricted Storage Account Access
Objective:
    • Use a Shared Access Signature (SAS) token to grant temporary, IP-restricted access
    • Scope: allow read and list operations on blob containers
    • Enforce access only from a specific IP range and time window

Security Context / Why We Do This:
    • A SAS token enables granular, time-bound access to storage resources without giving full credentials
    • This is ideal for:
        ○ Third-party developers
        ○ Temporary access during migration
        ○ Restricting downloads/uploads to a known IP or time
    • Prevents abuse of long-lived credentials by limiting what actions are allowed, from where, and for how long
    • SAS tokens can be revoked by regenerating storage account keys

Key Concepts from Video:
    • SAS tokens support service-level permissions (Blob, File, Queue, Table)
    • You must define what, who, how long, and from where when generating a token
    • SAS URLs can be embedded in scripts, apps, or sent to external parties
    • Tip: Store SAS usage logs using Storage analytics

Portal Steps:
    1. Navigate to Storage Account
        ○ Go to Storage Accounts > Choose your storage (e.g., mystorageeast)
        ○ Under Settings, click Shared access signature
    2. Configure SAS Settings
        ○ Services: Select only Blob
        ○ Resource types: Select Container and Object
        ○ Permissions: Check Read and List
        ○ Start time: Set current date/time
        ○ Expiry time: Set a future date/time (e.g., 2 hours later)
        ○ Allowed IP addresses: Enter range (e.g., 192.168.100.0/24)
        ○ Allowed protocols: HTTPS only
        ○ Click Generate SAS and connection string
    3. Copy and Share SAS URL
        ○ Copy the generated SAS token or full blob URL with query string
        ○ Paste into browser or use in PowerShell/CLI to test

PowerShell:
# Connect to storage account context
$ctx = New-AzStorageContext -StorageAccountName "mystorageeast" -StorageAccountKey "<storageKey>"
# Generate SAS for container
New-AzStorageContainerSASToken `
  -Name "backups" `
  -Context $ctx `
  -Permission rl `
  -StartTime (Get-Date) `
  -ExpiryTime (Get-Date).AddHours(2) `
  -Protocol HttpsOnly `
  -IPAddressOrRange "192.168.100.0/24" `
  -FullUri

Azure CLI:
# Generate SAS token for container
az storage container generate-sas \
  --account-name mystorageeast \
  --name backups \
  --permissions rl \
  --expiry "$(date -u -d '2 hours' +%Y-%m-%dT%H:%MZ)" \
  --ip "192.168.100.0/24" \
  --https-only \
  --auth-mode key \
  --output tsv
    🔐 Pro tip: Use the resulting SAS token in this format:
    https://mystorageeast.blob.core.windows.net/backups?<sas_token_here>

## Configuring Time-limited Restricted Storage Account Access


7. Configuring Time-Limited Restricted Storage Account Access
Objective:
    • Use a Shared Access Signature (SAS) token to grant temporary, IP-restricted access
    • Scope: allow read and list operations on blob containers
    • Enforce access only from a specific IP range and time window

Security Context / Why We Do This:
    • A SAS token enables granular, time-bound access to storage resources without giving full credentials
    • This is ideal for:
        ○ Third-party developers
        ○ Temporary access during migration
        ○ Restricting downloads/uploads to a known IP or time
    • Prevents abuse of long-lived credentials by limiting what actions are allowed, from where, and for how long
    • SAS tokens can be revoked by regenerating storage account keys

Key Concepts from Video:
    • SAS tokens support service-level permissions (Blob, File, Queue, Table)
    • You must define what, who, how long, and from where when generating a token
    • SAS URLs can be embedded in scripts, apps, or sent to external parties
    • Tip: Store SAS usage logs using Storage analytics

Portal Steps:
    1. Navigate to Storage Account
        ○ Go to Storage Accounts > Choose your storage (e.g., mystorageeast)
        ○ Under Settings, click Shared access signature
    2. Configure SAS Settings
        ○ Services: Select only Blob
        ○ Resource types: Select Container and Object
        ○ Permissions: Check Read and List
        ○ Start time: Set current date/time
        ○ Expiry time: Set a future date/time (e.g., 2 hours later)
        ○ Allowed IP addresses: Enter range (e.g., 192.168.100.0/24)
        ○ Allowed protocols: HTTPS only
        ○ Click Generate SAS and connection string
    3. Copy and Share SAS URL
        ○ Copy the generated SAS token or full blob URL with query string
        ○ Paste into browser or use in PowerShell/CLI to test

PowerShell:
# Connect to storage account context
$ctx = New-AzStorageContext -StorageAccountName "mystorageeast" -StorageAccountKey "<storageKey>"
# Generate SAS for container
New-AzStorageContainerSASToken `
  -Name "backups" `
  -Context $ctx `
  -Permission rl `
  -StartTime (Get-Date) `
  -ExpiryTime (Get-Date).AddHours(2) `
  -Protocol HttpsOnly `
  -IPAddressOrRange "192.168.100.0/24" `
  -FullUri

Azure CLI:
# Generate SAS token for container
az storage container generate-sas \
  --account-name mystorageeast \
  --name backups \
  --permissions rl \
  --expiry "$(date -u -d '2 hours' +%Y-%m-%dT%H:%MZ)" \
  --ip "192.168.100.0/24" \
  --https-only \
  --auth-mode key \
  --output tsv
    🔐 Pro tip: Use the resulting SAS token in this format:
    https://mystorageeast.blob.core.windows.net/backups?<sas_token_here>


## Creating a Compliant Cloud Sandbox


8. Creating a Compliant Cloud Sandbox
Objective:
    • Use Azure Blueprints to deploy a secure, policy-compliant sandbox:
        ○ Create a resource group named Sandbox
        ○ Assign Contributor access to a group named App1
        ○ Enforce policies: SQL auditing and allowed locations (East US only)

Security Context / Why We Do This:
    • Cloud sandboxes are often used for testing, training, or staging with minimal risk to production
    • Applying RBAC + Azure Policy ensures:
        ○ No unauthorized role sprawl
        ○ Resources stay in approved locations
        ○ Compliance mandates (like CIS, FedRAMP) are enforced automatically
    • Blueprints support repeatable deployments, version control, and auditable governance

Key Concepts from Video:
    • Blueprints are higher-level governance tools that combine:
        ○ Resource templates
        ○ Role assignments
        ○ Policy assignments
    • They ensure that each new environment is built securely by design
    • Blueprint assignments are tracked and can be locked from tampering

Portal Steps:
    1. Create a Blueprint
        ○ Go to Azure Blueprints > Create > Start with a Blank blueprint
        ○ Name: CompliantSandbox
        ○ Assign to a Management Group or Subscription
    2. Add Artifacts to the Blueprint
        ○ Click Add artifact → Select type: Resource group
            § Name: Sandbox, Location: East US
        ○ Add Role Assignment:
            § Role: Contributor
            § Principal: Azure AD Group App1
        ○ Add Policy Assignment:
            § Policy: Audit SQL server configurations
            § Policy: Allowed Locations → Set to only allow East US
    3. Publish and Assign the Blueprint
        ○ Click Publish blueprint → Add version (e.g., v1.0)
        ○ Click Assign blueprint
            § Select Subscription
            § Lock Assignment: Read Only or Do Not Lock
            § Enter parameter values (e.g., location = East US)
            § Click Assign

PowerShell:
    ⚠️ PowerShell support for Blueprints requires the Az.Blueprint module (may need manual install)
# Install module if needed
Install-Module -Name Az.Blueprint
# Define blueprint
New-AzBlueprint -Name "CompliantSandbox" -SubscriptionId <subId> -DisplayName "Compliant Cloud Sandbox"
# Add resource group artifact
New-AzBlueprintArtifact `
  -BlueprintName "CompliantSandbox" `
  -ArtifactName "SandboxRG" `
  -ResourceGroupArtifact `
  -DisplayName "Sandbox RG" `
  -ResourceGroupName "Sandbox" `
  -Location "East US"
# Assign contributor role to group
New-AzBlueprintArtifact `
  -BlueprintName "CompliantSandbox" `
  -ArtifactName "ContributorRole" `
  -RoleAssignmentArtifact `
  -DisplayName "Contributor Access" `
  -PrincipalId <GroupObjectId> `
  -RoleDefinitionId "/subscriptions/<subId>/providers/Microsoft.Authorization/roleDefinitions/<ContributorRoleId>"
# Assign the blueprint
Set-AzBlueprintAssignment -Name "CompliantSandbox" -SubscriptionId <subId>

Azure CLI:
    ❌ Azure CLI does not support Blueprints natively.
    ✅ Use ARM templates or REST API for automation.
    ⚙️ Workaround CLI path: deploy equivalent with az deployment sub create and policy assignments:
# Assign 'Allowed Locations' policy manually
az policy assignment create \
  --name "LimitLocations" \
  --policy "b24988ac-6180-42a0-ab88-20f7382dd24c" \
  --params '{ "listOfAllowedLocations": { "value": [ "eastus" ] } }' \
  --scope "/subscriptions/<subId>"
# Assign 'Audit SQL configurations'
az policy assignment create \
  --name "AuditSQL" \
  --policy "0e3a6b26-1e2e-4b6b-89f3-4b61b6359c79" \
  --scope "/subscriptions/<subId>"


## Generating Key Vault Secrets

9. Generating Key Vault Secrets
Objective:
In Key Vault KVCentral, you will:
    • Store a database connection string as a secret
    • Generate a self-signed certificate named WebApp1 with subject CN=www.webapp1.local
    • Create an encryption key (Key1) using RSA 2048-bit key

Security Context / Why We Do This:
    • Key Vault is a centralized tool to securely manage:
        ○ Secrets: passwords, connection strings, API keys
        ○ Keys: encryption keys for services like SQL TDE, VM disk encryption
        ○ Certificates: SSL/TLS for websites and apps
    • Avoids hardcoding secrets in source code or storing them in unsecured files
    • Supports RBAC and access policies, plus full audit logging and integration with Managed Identity

Key Concepts from Video:
    • Never store secrets in plain text or local config files — always use Key Vault
    • Certificates can be self-signed or issued by a CA (e.g., DigiCert, Sectigo)
    • Keys can be used in services like Disk Encryption, Azure SQL, or Custom Apps
    • Access is tightly controlled with role-based access or legacy access policies

Portal Steps:
    1. Create a Key Vault (if needed):
        ○ Azure Portal > Key Vaults > + Create
        ○ Name: KVCentral
        ○ Resource group: App1
        ○ Region: Central US
        ○ Pricing tier: Standard
        ○ Enable soft-delete and RBAC permissions model
    2. Add a Secret:
        ○ Navigate to KVCentral > Secrets > + Generate/Import
        ○ Upload method: Manual
        ○ Name: DBConnectionString1
        ○ Value: Server=sqlserver01;Database=appdb;User Id=admin;Password=SecureP@ssw0rd
        ○ Click Create
    3. Create a Key:
        ○ Navigate to KVCentral > Keys > + Generate
        ○ Name: Key1
        ○ Key type: RSA
        ○ RSA key size: 2048
        ○ Click Create
    4. Create a Certificate:
        ○ Navigate to KVCentral > Certificates > + Generate/Import
        ○ Method: Generate
        ○ Name: WebApp1
        ○ Certificate Type: Self-signed
        ○ Subject: CN=www.webapp1.local
        ○ Validity: 12 months (default)
        ○ Click Create

PowerShell:
# Create a Key Vault (if needed)
New-AzKeyVault -Name "KVCentral" -ResourceGroupName "App1" -Location "Central US"
# Add a secret
Set-AzKeyVaultSecret `
  -VaultName "KVCentral" `
  -Name "DBConnectionString1" `
  -SecretValue (ConvertTo-SecureString "Server=sqlserver01;Database=appdb;User Id=admin;Password=SecureP@ssw0rd" -AsPlainText -Force)
# Create a software-protected key
Add-AzKeyVaultKey `
  -VaultName "KVCentral" `
  -Name "Key1" `
  -Destination "Software"
# Create a self-signed certificate
$policy = Get-AzKeyVaultCertificatePolicy -SubjectName "CN=www.webapp1.local"
Add-AzKeyVaultCertificate `
  -VaultName "KVCentral" `
  -Name "WebApp1" `
  -Policy $policy

Azure CLI:
# Create Key Vault
az keyvault create \
  --name KVCentral \
  --resource-group App1 \
  --location "centralus"
# Add secret
az keyvault secret set \
  --vault-name KVCentral \
  --name DBConnectionString1 \
  --value "Server=sqlserver01;Database=appdb;User Id=admin;Password=SecureP@ssw0rd"
# Create key
az keyvault key create \
  --vault-name KVCentral \
  --name Key1 \
  --protection software \
  --kty RSA \
  --size 2048
# Create certificate
az keyvault certificate create \
  --vault-name KVCentral \
  --name WebApp1 \
  --policy "$(az keyvault certificate get-default-policy --subject 'CN=www.webapp1.local')"

