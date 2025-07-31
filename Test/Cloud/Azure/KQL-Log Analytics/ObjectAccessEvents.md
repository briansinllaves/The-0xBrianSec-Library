### Event ID 4670: Permissions on an object were changed
```kql
SecurityEvent
| where EventID == 4670
| project TimeGenerated, SubjectUserName, ObjectName, ObjectType, OperationType
| sort by TimeGenerated desc
```
<!--- Tracks changes to object permissions. Useful for detecting privilege escalation or unauthorized access configuration. -->

### Event ID 4661: A handle to an object was requested
```kql
SecurityEvent
| where EventID == 4661
| project TimeGenerated, SubjectUserName, ObjectName, ObjectType, AccessMask
| sort by TimeGenerated desc
```
<!--- Indicates an attempt to access an object before permissions are checked. -->

### Event ID 4656: A handle to an object was requested with specific access rights
```kql
SecurityEvent
| where EventID == 4656
| project TimeGenerated, SubjectUserName, ObjectName, AccessMask, ObjectType
| sort by TimeGenerated desc
```
<!--- Useful for tracking object-level access attempts. -->

### Event ID 4690: An attempt was made to duplicate a handle to an object
```kql
SecurityEvent
| where EventID == 4690
| project TimeGenerated, SubjectUserName, ObjectName, HandleId
| sort by TimeGenerated desc
```
<!--- Rare but useful in detecting token manipulation or process handle abuse. -->

