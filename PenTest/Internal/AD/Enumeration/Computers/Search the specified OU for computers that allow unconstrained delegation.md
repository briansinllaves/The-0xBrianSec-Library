```
 Get-DomainComputer -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -Unconstrained
```

Tactic: If you've gained access to a computer with unconstrained delegation enabled, it allows you to impersonate any domain user, including administrators, and authenticate to services trusted by the user account and any other services as that user.
