# EnableResourceLocking

## Azure Resource Locks


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

## Managing Azure Resource Locks Using the Portal


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

