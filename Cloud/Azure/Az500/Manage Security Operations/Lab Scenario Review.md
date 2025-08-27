# In-Depth Study Notes: Managing Azure Security

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
