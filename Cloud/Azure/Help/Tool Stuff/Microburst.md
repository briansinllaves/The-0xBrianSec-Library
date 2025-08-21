```

Import-Module .\MicroBurst-master\MicroBurst.psm1 -Verbose


```

https://github.com/NetSPI/MicroBurst


find Azure services exposed

```
Import-Module .\MicroBurst\MicroBurst.psm1 -Verbose
Invoke-EnumerateAzureSubDomains -Base corp -Verbose
```