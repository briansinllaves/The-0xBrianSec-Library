### Event ID 4720–4738: Account lifecycle events
```kql
SecurityEvent
| where EventID in (4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4738)
| project TimeGenerated, EventID, TargetUserName, SubjectUserName, OperationType
| sort by TimeGenerated desc
```
<!--- Tracks creation, deletion, enabling, disabling, password changes, and group modifications of user accounts. -->

