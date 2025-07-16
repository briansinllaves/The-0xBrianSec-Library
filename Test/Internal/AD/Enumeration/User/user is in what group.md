```
 Get-DomainGroup -MemberIdentity IN_a01 -Domain asdf.local -Server 10ip0 | select -ExpandProperty samaccountne -recurse
```
