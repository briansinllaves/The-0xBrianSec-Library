# Security Log Search Queries

## Search for Specific EventID  
> **Note:** Filter by event IDs for object access.  
```kql
SecurityEvent
| where EventID == 4663
| project TimeGenerated, EventID, Computer, Account, ProcessId, ProcessName, ServiceName
| sort by TimeGenerated desc
```

## By specific EventID and Computer  
> **Note:** Filter by logon/logout event IDs.  
```kql
SecurityEvent
| where EventID in (4624, 4625, 5140)
| project TimeGenerated, EventID, Computer, Account
| sort by TimeGenerated desc
```

## Privileged Activities  
> **Note:** Detect special privileges assignment.  
```kql
SecurityEvent
| where EventID == 4672
| project TimeGenerated, EventID, Computer, Account
| sort by TimeGenerated desc
```

## Concurrent Logons  
> **Note:** Find concurrent logons from different workstations within 1 hour.  
```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, Computer
| summarize LogonCount = count(), Computers = makeset(Computer) by Account, bin(TimeGenerated, 1h)
| where LogonCount > 1 and array_length(Computers) > 1
| project Account, TimeGenerated, Computers
| sort by TimeGenerated desc
```

## Account Management Events  
> **Note:** Track creations, modifications, and deletions of accounts.  
```kql
SecurityEvent
| where EventID in (4720, 4722, 4723, 4724, 4725, 4726, 4732, 4738)
| where TimeGenerated >= datetime(2030-MM-DD) and TimeGenerated < datetime(2030-MM-DD)
| project TimeGenerated, EventID, Account, Activity = OperationName, Computer
| sort by TimeGenerated desc
```