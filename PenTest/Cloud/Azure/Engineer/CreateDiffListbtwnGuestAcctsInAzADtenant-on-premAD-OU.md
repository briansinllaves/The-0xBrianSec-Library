# CreateDiffListbtwnGuestAcctsInAzADtenant-on-premAD-OU

```powershell
$azGuests = Get-AzADUser | Where-Object { $_.UserType -eq "Guest" }
$onPremAD = Get-ADUser -Filter * -SearchBase "OU=Users,DC=domain,DC=local"
Compare-Object -ReferenceObject $azGuests.UserPrincipalName -DifferenceObject $onPremAD.UserPrincipalName
```
