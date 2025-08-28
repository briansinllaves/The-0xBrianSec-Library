# Enable Resource Locking

## Azure Resource Locks

### What Are Azure Resource Locks?

* Protect resources from accidental changes or deletion.
* Applied at:

  * Subscription
  * Resource Group
  * Individual Resource
* Override RBAC: even Owner/Contributor cannot delete or modify when lock is applied.

### Why Use Resource Locks?

* Prevent accidental deletion or modification.
* Critical for production and compliance.
* Enforce governance beyond RBAC.

### Lock Types

1. **ReadOnly**

   * Resource can be read.
   * Cannot update or delete.
   * Example: Storage Account keys cannot be listed; no config changes allowed.
2. **CanNotDelete**

   * Resource can be modified.
   * Cannot be deleted.
   * Example: VM can be updated but not deleted.

### Scope and Inheritance

* Subscription lock → applies to all groups/resources.
* Resource Group lock → applies to all resources inside.
* New resources inherit lock status.
* Most restrictive lock applies.

### Control Plane vs Data Plane

* **Control plane** (resource lifecycle/config) → ✅ affected.
* **Data plane** (actual data ops like blob writes, SQL queries) → ❌ not affected.

### Behavior Examples

* CanNotDelete on Storage Account: prevents deletion of account, but blobs can still be deleted.
* ReadOnly on VM: prevents resize/reconfig/delete, but properties can still be read.

### Notes for AZ-500

* Locks apply immediately and persist until removed.
* Must remove lock before deleting.
* Managed via Portal, ARM templates, CLI, PowerShell.
* Governance enforcement: use with Policy, RBAC, Blueprints.

---

## Managing Azure Resource Locks Using the Portal

* Prevent accidental deletion/modification.
* Override Contributor RBAC.

### Lock Types

* **Read-only**: Prevents configuration changes.
* **Delete**: Prevents resource deletion.

### Hierarchical Application

* Management Group → No lock option in portal.
* Subscription → Settings → Resource Locks.
* Resource Group → Settings → Locks.
* Resource → Settings → Locks.
* Inherited downward.
* Most restrictive lock wins.

### Portal Navigation

**Subscription**

1. Go to Subscriptions → Select subscription.
2. Settings → Resource locks.
3. Add lock: name, type, note.

**Resource Group**

1. Go to Resource groups → Select group.
2. Settings → Locks.
3. View/edit/delete locks.

**Resource**

1. Go to All resources → Select resource.
2. Settings → Locks.

### Example: Read-only Lock on Storage Account

* Blocks access keys, networking config changes.
* Error in portal: *“Failed to save firewall and virtual network settings”*.

### Removing Locks

* Must remove at the level it was applied.
* Example: Subscription lock must be removed at subscription.

### Best Practices

* Use in production and audit-sensitive zones.
* Always document locks (Notes field).
* Combine with Policy and Blueprints.

---

## Managing Azure Resource Locks Using the CLI

### Purpose

* Prevent accidental deletion/modification.
* Override Contributor RBAC.
* Not true security — privileged users can remove locks.

### Lock Types

* **CanNotDelete**: prevents deletion.
* **ReadOnly**: prevents modify + delete.

### CLI Scope

* `az account lock` → Subscription
* `az group lock` → Resource Group
* `az resource lock` → Individual Resource

### Create Locks

**Subscription**

```bash
az account lock create --name "CannotDeleteSub" --lock-type CanNotDelete
az account lock list
```

**Resource Group**

```bash
az group lock create --lock-type ReadOnly -n NoModify -g App1
az group lock list -g App1
```

**Resource**

```bash
az resource lock create \
  --lock-type ReadOnly \
  --name NoModify \
  --resource eastyhz1 \
  --resource-type Microsoft.Storage/storageAccounts \
  --resource-group App1
```

### View Lock

```bash
az account lock show --name "CannotDeleteSub"
```

### Delete Locks

**Subscription**

```bash
az account lock delete --name "CannotDeleteSub"
```

**Resource Group**

```bash
az group lock delete --name "NoModify" --resource-group App1
```

**Resource**

```bash
az resource lock delete \
  --name "NoModify" \
  --resource-group App1 \
  --resource-type Microsoft.Storage/storageAccounts \
  --resource eastyhz1
```

---

## Managing Azure Resource Locks Using PowerShell

### Cmdlets

```powershell
Get-Command *lock* -Type Cmdlet
# Get-AzResourceLock, New-AzResourceLock, Set-AzResourceLock, Remove-AzResourceLock
```

### View Locks

```powershell
Get-AzResourceLock
Get-AzResourceLock -ResourceGroupName "App1"
```

### Create Lock

```powershell
New-AzResourceLock -LockName "NoModify" -LockLevel ReadOnly -ResourceGroupName "App1" -Force
```

### Modify Lock

```powershell
Set-AzResourceLock -LockName "NoModify" -LockLevel CanNotDelete -ResourceGroupName "App1"
```

### Remove Lock

```powershell
Remove-AzResourceLock -ResourceGroupName "App1" -Name "NoModify" -Force
```

---

## Enabling Resource Locking with Templates

### Purpose

* Automate governance with ARM templates.
* Apply locks during deployment.
* Prevent accidental deletion.

### Template

* Resource group created.
* Lock applied (`CanNotDelete`).
* Role assignment included.

### Deploy via Portal

1. Deploy template.
2. Provide Subscription, Region, rgName, rgLocation, principalId.
3. Create.

### Resources Created

* Resource Group
* Lock (Microsoft.Authorization/locks)
* RBAC Assignment

### Validate

* Check IAM → Contributor role assigned.
* Check Locks → Lock listed.

### Best Practices

* Use with RBAC and Policy for full governance.
* Document purpose of lock.
* Validate after deployment.
