# ConnectUsingaServicePrincipalUsefulforScripting

```powershell
Connect-AzAccount -ServicePrincipal `
  -Tenant <tenant-id> `
  -ApplicationId <app-id> `
  -Credential (ConvertTo-SecureString "<client-secret>" -AsPlainText -Force)
```
