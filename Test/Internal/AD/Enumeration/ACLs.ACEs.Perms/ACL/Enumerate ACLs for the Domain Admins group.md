```powershell
# Enumerate ACLs for the Domain Admins group

Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
```
