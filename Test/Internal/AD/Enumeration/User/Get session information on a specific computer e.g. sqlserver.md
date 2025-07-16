 
 
 
 We could use this to check sessions on a ‘sqlserver’ host or a local host or even domain controllers. If we know the creds of the admin, we could login and take over that admin session. We can find SessionIDs to help with tracking network connections. 
Tactic: Query the function on the domain controllers and files shares to identify systems which privileged users had recently authenticated against


```
Get-NetSession -Computerne sqlserver

```

**![](https://lh7-us.googleusercontent.com/427q2zFoygsuJrx4r2eS7zAcgeYNLK0CtkMBOIFIAobeMEhStx5ObEc0HHkedQFSlkNBOpsDGF346BKtq6wwLaMwCtJP8Uk-GHZBSRBilCwGYhwMNi-zdJX-BGDehrU94-zxqTnmLaazY7caQK-Dj1ej4KWj1T2q)**
