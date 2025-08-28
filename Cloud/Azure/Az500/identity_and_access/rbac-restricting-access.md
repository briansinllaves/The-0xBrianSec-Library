# Restricting Resource Access with Roles (RBAC)

## Commands

```bash
# Azure CLI
az role definition list --query [].roleName
az role assignment create --assignee user@contoso.com --role "Reader" --resource-group APP1
az role assignment list --resource-group APP1
az role assignment delete --assignee user@contoso.com --role "Reader" --resource-group APP1
```

```powershell
# PowerShell
New-AzRoleAssignment -SignInName user@contoso.com -RoleDefinitionName "Reader" -ResourceGroupName APP1
Get-AzRoleAssignment -ResourceGroupName APP1
```

---

## Q\&A

**Problem with CLI statement?**

* The role has not been specified ✅

**Scopes for role assignments?**

* Management group ✅
* Subscription ✅

**Custom role syntax?**

* JSON ✅

**PowerShell to view assignments?**

* Get-AzRoleAssignment ✅

**Portal click to grant Reader?**

* Access Control (IAM) ✅
