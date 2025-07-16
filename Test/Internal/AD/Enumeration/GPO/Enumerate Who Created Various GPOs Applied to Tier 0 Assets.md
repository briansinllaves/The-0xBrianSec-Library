
This command will help you identify the creators of various GPOs that are applied to Tier 0 assets and have the 'GenericAll' permission.
```
Invoke-ACLScanner -ResolveGUIDs -ADSPath 'OU=' | Where-Object {$_.ActiveDirectoryRights -eq 'GenericAll'}
```

