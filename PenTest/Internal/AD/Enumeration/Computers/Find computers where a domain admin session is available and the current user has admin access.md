```
**Find-DomainUserLocation -UserGroupIdentity “Administrators” -CheckAccess**
```

Tactic: Identify computers accessed/logged in by a domain admin or a specific user/group and to narrow the focus onto specific targets so we can gather hashes to achieve privilege escalation. -CheckAccess will check if the current user has local admin access to computers where target users are found. 

