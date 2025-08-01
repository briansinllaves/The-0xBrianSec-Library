
```
Find-DomainUserLocation -Verbose

Find-DomainUserLocation -UserGroupIdentity “Administrators"

Find-DomainUserLocation -UserGroupIdentity "RDPUsers”
```

Tactic: Identify computers accessed/logged in by a domain admin or a specific user/group and to narrow the focus onto specific targets so we can gather hashes to achieve privilege escalation, etc.  