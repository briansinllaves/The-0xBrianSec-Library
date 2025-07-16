

```
Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=blah,DC=com" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl
```