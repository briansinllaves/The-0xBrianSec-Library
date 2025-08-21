# SearchforAzResourceorAcctInfoCLI

```bash
az ad user list --query "[].{Name:displayName, UPN:userPrincipalName}"
az resource list --query "[?contains(name, 'prod')]" -o table
```
