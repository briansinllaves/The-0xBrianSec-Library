 
 
 
 We could use this to check sessions on a ‘sqlserver’ host or a local host or even domain controllers. If we know the creds of the admin, we could login and take over that admin session. We can find SessionIDs to help with tracking network connections. 
Tactic: Query the function on the domain controllers and files shares to identify systems which privileged users had recently authenticated against


```
Get-NetSession -Computerne sqlserver

```
