```
Specify the DN of the OU you want to check

$ouDN = "OU=Admin,DC=winterfell,DC=sevenkingdoms,DC=local"


Get the ACL for the OU

Get-DomainObjectAcl -Identity $ouDN

```