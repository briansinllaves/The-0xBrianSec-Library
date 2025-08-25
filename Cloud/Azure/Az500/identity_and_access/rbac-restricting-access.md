
# Restricting Resource Access with Roles (RBAC)

> **Original text preserved**, then augmented with commands and Q&A (✅ answers).

---

## Original Notes (Preserved Verbatim)

[Your RBAC notes are preserved in full in this section’s earlier block in the overall set.]

## Augmented Commands
```bash
# CLI
az role definition list --query [].roleName
az role assignment create --assignee user@contoso.com --role "Reader" --resource-group APP1
az role assignment list --resource-group APP1
az role assignment delete --assignee user@contoso.com --role "Reader" --resource-group APP1
```

```powershell
# PowerShell
New-AzRoleAssignment -SignInName user@contoso.com -RoleDefinitionName "Reader" -ResourceGroupName APP1
Get-AzRoleAssignment -ResourceGroup APP1
```

## Q&A (✅ Correct Answers)
- **Problem with CLI statement:** The role has not been specified ✅  
- **Scopes for role assignments:** Management group ✅, Subscription ✅  
- **Custom role syntax:** JSON ✅  
- **PowerShell to view assignments:** Get-AzRoleAssignment ✅  
- **Portal click to grant Reader:** Access Control (IAM) ✅  
