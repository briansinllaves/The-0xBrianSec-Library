# Managing Azure Security

## Managing User Permissions to Azure Resources

### Objective

* Implement least-privilege access by grouping users dynamically (e.g., city = Toronto).
* Assign appropriate RBAC roles at the resource level.
* Permissions auto-scale as user attributes match group rules.

### Why It Matters

* Prevents over-provisioning.
* Supports dynamic environments (e.g., hiring in Toronto auto-adds access).
* Aligns with Zero Trust.

### Portal Steps

1. **Create Dynamic Group**

   * Azure AD > Groups > + New group
   * Group type: Security
   * Name: `Toronto_Users`
   * Membership type: Dynamic User
   * Add owner: Abu Adachi
   * Rule: City = Toronto
2. **Add User**

   * Azure AD > Users > + New user
   * Name: Julio Chavez, UPN: `jchavez@yourdomain.com`
   * Set City = Toronto
3. **Assign Role to Group**

   * Resource Group > App1 > IAM > Add Role Assignment
   * Role: Storage Blob Data Reader
   * Assign to: Group → Toronto\_Users

### PowerShell

```powershell
# Create user
New-AzADUser -DisplayName "Julio Chavez" -UserPrincipalName "jchavez@yourdomain.com" `
  -MailNickname "jchavez" -PasswordProfile @{Password="Password123!"; ForceChangePasswordNextLogin=$true} `
  -AccountEnabled $true -UsageLocation "CA"

# Set user city
Update-MgUser -UserId "jchavez@yourdomain.com" -City "Toronto"

# Create dynamic group
$rule = '(user.city -eq "Toronto")'
New-MgGroup -DisplayName "Toronto_Users" -MailEnabled:$false -MailNickname "torontousers" `
  -SecurityEnabled:$true -GroupTypes @("DynamicMembership") `
  -MembershipRule $rule -MembershipRuleProcessingState "On"

# Assign role
$group = Get-AzADGroup -DisplayName "Toronto_Users"
New-AzRoleAssignment -ObjectId $group.Id -RoleDefinitionName "Storage Blob Data Reader" -ResourceGroupName "App1"
```

### Azure CLI

```bash
# Create user
az ad user create --display-name "Julio Chavez" \
  --user-principal-name jchavez@yourdomain.com \
  --password "Password123!" --force-change-password-next-login true

# Update user city
az rest --method patch --uri "https://graph.microsoft.com/v1.0/users/jchavez@yourdomain.com" \
  --headers "Content-Type=application/json" \
  --body '{"city":"Toronto"}'

# Create group
az ad group create --display-name "Toronto_Users" --mail-nickname "torontousers"

# Update group to dynamic membership
az rest --method patch --uri "https://graph.microsoft.com/v1.0/groups/<groupId>" \
  --headers "Content-Type=application/json" \
  --body '{ "groupTypes":["DynamicMembership"], "membershipRuleProcessingState":"On", "membershipRule":"(user.city -eq \"Toronto\")" }'

# Assign role
az role assignment create --assignee <group-object-id> --role "Storage Blob Data Reader" --resource-group App1
```

---

## Defining Custom RBAC Roles

### Objective

* Create a custom RBAC role:

  * Full **VM management**
  * **Read-only Blob storage**
  * Scope: Resource group App1

### Why It Matters

* Built-in roles may not align with business needs.
* Granularity enforces least privilege.
* Restricts scope → reduces lateral movement.

### Portal Steps

1. Subscriptions > Access control (IAM) > + Add custom role.
2. Name: `Custom VM Management`.
3. Actions:

   * `Microsoft.Compute/*`
   * `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`
4. Assignable Scope: `/subscriptions/<subId>/resourceGroups/App1`.
5. Assign to user Abu.

### PowerShell

```powershell
# Custom role JSON
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
$roleJson | Out-File "./customRole.json"
New-AzRoleDefinition -InputFile "./customRole.json"

# Assign to Abu
$user = Get-AzADUser -DisplayName "Abu"
New-AzRoleAssignment -ObjectId $user.Id -RoleDefinitionName "Custom VM Management" -Scope "/subscriptions/<subId>/resourceGroups/App1"
```

### Azure CLI

```bash
# Role JSON
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

# Create role
az role definition create --role-definition custom-role.json

# Assign to Abu
userId=$(az ad user show --id abu@yourdomain.com --query id -o tsv)
az role assignment create \
  --assignee $userId \
  --role "Custom VM Management" \
  --scope "/subscriptions/<subId>/resourceGroups/App1"
```

---

## Configuring Conditional Access Policies

### Objective

* Require MFA for app **Mobile Xpense**.
* Allow only **Android devices** from **trusted subnet**.

### Why It Matters

* Blocks access from unknown/untrusted devices.
* Mitigates credential theft (phishing, reuse).
* Meets compliance (location/device-aware).

### Portal Steps

1. **Named Location:** Security > Named Locations → Add IP range `192.168.1.0/24` (trusted).
2. **Policy:** Security > Conditional Access → New Policy.

   * Users: All.
   * App: Mobile Xpense.
   * Conditions: Device = Android, Location = HQ Europe.
   * Access: Grant → Require MFA.
   * Enable Policy: On.

### PowerShell

```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Trusted location
New-MgConditionalAccessNamedLocation -DisplayName "Headquarters Europe" `
  -IpRange @{Ranges="192.168.1.0/24"; IsTrusted=$true}

# Policy
New-MgConditionalAccessPolicy -DisplayName "Allow Access to Mobile Xpense" `
  -State "enabled" `
  -Conditions @{
      Users = @{Include = @("All")}
      Platforms = @{Include = @("android")}
      Locations = @{Include = @("<location-id>")}
    } `
  -GrantControls @{BuiltInControls = @("mfa")} `
  -Applications @{IncludeApplications = @("<mobile-xpense-app-id>")}
```

---

## Assigning Permissions to Azure VMs

### Objective

* Enable **System-Assigned Managed Identity** on VM `WinSrv2019-2`.
* Assign **Storage Blob Data Reader** role to access blobs in App1 RG.

### Portal Steps

1. VM → Identity → System-assigned = On.
2. Storage Account → IAM → Add role → Storage Blob Data Reader → Assign to VM identity.

### PowerShell

```powershell
# Enable system-assigned MI
$vm = Get-AzVM -Name "WinSrv2019-2" -ResourceGroupName "App1"
$vm.Identity.Type = 'SystemAssigned'
Update-AzVM -VM $vm -ResourceGroupName "App1"

# Get principal ID
$identity = (Get-AzVM -ResourceGroupName "App1" -Name "WinSrv2019-2").Identity.PrincipalId

# Assign role
New-AzRoleAssignment `
  -ObjectId $identity `
  -RoleDefinitionName "Storage Blob Data Reader" `
  -Scope "/subscriptions/<subId>/resourceGroups/App1/providers/Microsoft.Storage/storageAccounts/<storageAccountName>"
```

### Azure CLI

```bash
# Enable MI
az vm identity assign --name WinSrv2019-2 --resource-group App1

# Get principal ID
principalId=$(az vm show -g App1 -n WinSrv2019-2 --query identity.principalId -o tsv)

# Assign role
az role assignment create \
  --assignee $principalId \
  --role "Storage Blob Data Reader" \
  --scope "/subscriptions/<subId>/resourceGroups/App1/providers/Microsoft.Storage/storageAccounts/<storageAccountName>"
```

---

## Hardening Azure SQL Managed Instance

### Objective

* Enable **TDE**.
* Enable **Defender for SQL**.
* Configure **backups**.
* Apply **Dynamic Data Masking**.
* Restrict via **firewall rules**.

### Portal Steps

1. DB → Security → TDE = On.
2. Defender for Cloud → Enable Defender for SQL.
3. SQL Server → Backups → Set retention.
4. DB → Security → DDM → Add rules.
5. SQL Server → Networking → Add IP range.

### PowerShell

```powershell
# Enable TDE
Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName "App1" -ServerName "sqlserver01" -DatabaseName "db1" -State "Enabled"

# Enable Defender
Set-AzSqlServerThreatDetectionPolicy -ResourceGroupName "App1" -ServerName "sqlserver01" -State Enabled

# Firewall rule
New-AzSqlServerFirewallRule -ResourceGroupName "App1" -ServerName "sqlserver01" -FirewallRuleName "AllowMyIP" -StartIpAddress "192.168.1.1" -EndIpAddress "192.168.1.1"
```

### Azure CLI

```bash
# Enable TDE
az sql db tde set --resource-group App1 --server sqlserver01 --name db1 --status Enabled

# Enable Defender
az sql server threat-policy update --resource-group App1 --server sqlserver01 --state Enabled

# Firewall rule
az sql server firewall-rule create \
  --resource-group App1 \
  --server sqlserver01 \
  --name AllowMyIP \
  --start-ip-address 192.168.1.1 \
  --end-ip-address 192.168.1.1
```

---

## Configuring Time-Limited Restricted Storage Account Access

### Objective

* Use SAS token to grant **time-limited, IP-restricted** access.
* Permissions: Read + List.

### Portal Steps

1. Storage Account → Shared access signature.
2. Select services: Blob, Resource type: Container + Object.
3. Permissions: Read + List.
4. Set start/expiry time, IP range, HTTPS only.
5. Generate SAS.

### PowerShell

```powershell
$ctx = New-AzStorageContext -StorageAccountName "mystorageeast" -StorageAccountKey "<storageKey>"

New-AzStorageContainerSASToken `
  -Name "backups" `
  -Context $ctx `
  -Permission rl `
  -StartTime (Get-Date) `
  -ExpiryTime (Get-Date).AddHours(2) `
  -Protocol HttpsOnly `
  -IPAddressOrRange "192.168.100.0/24" `
  -FullUri
```

### Azure CLI

```bash
az storage container generate-sas \
  --account-name mystorageeast \
  --name backups \
  --permissions rl \
  --expiry "$(date -u -d '2 hours' +%Y-%m-%dT%H:%MZ)" \
  --ip "192.168.100.0/24" \
  --https-only \
  --auth-mode key \
  --output tsv
```

---

## Creating a Compliant Cloud Sandbox

### Objective

* Use **Blueprints** to create a secure sandbox:

  * RG = Sandbox.
  * Contributor role to group App1.
  * Policies = SQL auditing + Allowed Locations.

### Portal Steps

1. Blueprints → Create → Blank.
2. Add artifacts: Sandbox RG, Role assignment, Policy assignment.
3. Publish + Assign.

### PowerShell

```powershell
Install-Module -Name Az.Blueprint

New-AzBlueprint -Name "CompliantSandbox" -SubscriptionId <subId> -DisplayName "Compliant Cloud Sandbox"

# Sandbox RG artifact
New-AzBlueprintArtifact -BlueprintName "CompliantSandbox" -ArtifactName "SandboxRG" -ResourceGroupArtifact `
  -DisplayName "Sandbox RG" -ResourceGroupName "Sandbox" -Location "East US"

# Role artifact
New-AzBlueprintArtifact -BlueprintName "CompliantSandbox" -ArtifactName "ContributorRole" -RoleAssignmentArtifact `
  -DisplayName "Contributor Access" -PrincipalId <GroupObjectId> `
  -RoleDefinitionId "/subscriptions/<subId>/providers/Microsoft.Authorization/roleDefinitions/<ContributorRoleId>"

Set-AzBlueprintAssignment -Name "CompliantSandbox" -SubscriptionId <subId>
```

### Azure CLI

```bash
# Allowed Locations policy
az policy assignment create \
  --name "LimitLocations" \
  --policy "b24988ac-6180-42a0-ab88-20f7382dd24c" \
  --params '{ "listOfAllowedLocations": { "value": [ "eastus" ] } }' \
  --scope "/subscriptions/<subId>"

# SQL Audit policy
az policy assignment create \
  --name "AuditSQL" \
  --policy "0e3a6b26-1e2e-4b6b-89f3-4b61b6359c79" \
  --scope "/subscriptions/<subId>"
```

---

## Generating Key Vault Secrets

### Objective

* Store **DB connection string**.
* Create **RSA 2048 key**.
* Create **self-signed cert**.

### Portal Steps

1. Create Key Vault `KVCentral`.
2. Add secret `DBConnectionString1`.
3. Create key `Key1`.
4. Create cert `WebApp1` (CN=[www.webapp1.local](http://www.webapp1.local)).

### PowerShell

```powershell
# Vault
New-AzKeyVault -Name "KVCentral" -ResourceGroupName "App1" -Location "Central US"

# Secret
Set-AzKeyVaultSecret -VaultName "KVCentral" -Name "DBConnectionString1" `
  -SecretValue (ConvertTo-SecureString "Server=sqlserver01;Database=appdb;User Id=admin;Password=SecureP@ssw0rd" -AsPlainText -Force)

# Key
Add-AzKeyVaultKey -VaultName "KVCentral" -Name "Key1" -Destination "Software"

# Certificate
$policy = Get-AzKeyVaultCertificatePolicy -SubjectName "CN=www.webapp1.local"
Add-AzKeyVaultCertificate -VaultName "KVCentral" -Name "WebApp1" -Policy $policy
```

### Azure CLI

```bash
# Vault
az keyvault create --name KVCentral --resource-group App1 --location "centralus"

# Secret
az keyvault secret set --vault-name KVCentral --name DBConnectionString1 \
  --value "Server=sqlserver01;Database=appdb;User Id=admin;Password=SecureP@ssw0rd"

# Key
az keyvault key create --vault-name KVCentral --name Key1 --protection software --kty RSA --size 2048

# Certificate
az keyvault certificate create \
  --vault-name KVCentral \
  --name WebApp1 \
  --policy "$(az keyvault certificate get-default-policy --subject 'CN=www.webapp1.local')"
```
