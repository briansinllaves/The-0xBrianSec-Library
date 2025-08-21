# Azure Specific System Events

## Successful and unsuccessful logon events  
> **Note:** Logon events can be tracked using the `SigninLogs` table in Azure Log Analytics.  
```kql
SigninLogs
| where ResultType == "0" or ResultType != "0"
```

## Account management events  
> **Note:** Account management events can be found in the `AuditLogs` table.  
```kql
AuditLogs
| where Category == "UserManagement"
```

## Object access, privileged functions, and policy changes  
> **Note:** Object access and policy changes can be monitored using the `AzureActivity` table.  
```kql
AzureActivity
| where Caller contains "user123"
| where ActivityStatusValue == "Success"
| where TimeGenerated >= datetime(2030-MM-DD) and TimeGenerated < datetime(2030-MM-DD)
| project TimeGenerated, Caller, OperationName, ActivityStatusValue, Properties, ResourceId, OperationNameValue
| order by TimeGenerated desc

AzureActivity
| where CategoryValue == "Administrative"
| extend PolicyDetails = parse_json(Properties)
| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue, PolicyDetails
| order by TimeGenerated desc
```

## Process tracking  
> **Note:** Use the `SecurityEvent` table to track process creation and termination.  
```kql
SecurityEvent
| where EventID in (4688, 4689)
```

## System events  
> See **SecurityLogSearch.md** for system event queries.

## Specific resource-to-resource investigation  
```kql
AzureActivity
| where TimeGenerated >= datetime(2030-MM-DD)
| where ResourceId contains "userA" or ResourceId contains "userB"
| project TimeGenerated, Caller, OperationName, ActivityStatusValue, Properties, ResourceId, OperationNameValue, ResultDescription, SubscriptionId, EventSubmissionTimestamp, Level, Status
| order by TimeGenerated desc
```