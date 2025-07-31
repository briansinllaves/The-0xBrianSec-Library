### Event ID 5038: Code integrity failure
```kql
SecurityEvent
| where EventID == 5038
| project TimeGenerated, FileName, Hash, IntegrityStatus
| sort by TimeGenerated desc
```
<!--- Detects tampering or unsigned binaries loading into memory. -->

