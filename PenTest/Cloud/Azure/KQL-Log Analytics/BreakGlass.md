# Break Glass Account Monitoring

## Password Management  
> **Note:** Monitor password management activities using the `AuditLogs` table.  
```kql
AuditLogs
| where OperationName contains "password"
| extend InitiatedBy = tostring(InitiatedBy.user.displayName), TargetUser = tostring(TargetResources[0].userPrincipalName)
| where TargetUser contains "@example.onmicrosoft.com"
| project TimeGenerated, InitiatedBy, TargetUser, Result, OperationName, Category
| where TimeGenerated >= datetime(2030-MM-DD) and TimeGenerated < datetime(2030-MM-DD)
| order by TimeGenerated desc
```

## Auditing MFA  
> **Note:** Check if MFA is enabled on breakglass accounts in the `SigninLogs` table.  
```kql
SigninLogs
| where UserPrincipalName contains "@example.onmicrosoft.com"
| where TimeGenerated >= datetime(2030-MM-DD) and TimeGenerated < datetime(2030-MM-DD)
| where Status contains "MFA"
| project TimeGenerated, UserPrincipalName, IPAddress, Status, AuthenticationDetails
```

## Log-in Attempts  
> **Note:** Track log-in attempts.  
```kql
SigninLogs
| where UserPrincipalName contains "@example.onmicrosoft.com"
| project TimeGenerated, UserPrincipalName, ResultType, ResultDescription, AuthenticationRequirement
| order by TimeGenerated desc
```

## Access to Resources  
> **Note:** Monitor resource access by breakglass account.  
```kql
AzureActivity
| where Caller contains "@example.onmicrosoft.com"
| where TimeGenerated >= datetime(2030-MM-DD) and TimeGenerated < datetime(2030-MM-DD)
| project TimeGenerated, Caller, OperationName, Resource, ResourceGroup, ResourceId, Category, Properties, OperationNameValue, ResourceProviderValue
| order by TimeGenerated desc
```

## Configuration Changes  
> **Note:** Monitor configuration changes by breakglass account.  
```kql
AzureActivity
| where Caller contains "@example.onmicrosoft.com"
| where TimeGenerated >= datetime(2030-MM-DD) and TimeGenerated < datetime(2030-MM-DD)
| where ActivityStatus has "Succeeded"
| project TimeGenerated, Caller, Message = tostring(parse_json(Properties).message), Resource, ActivityStatus, Properties
| order by TimeGenerated desc
```

## Directory Services Interaction  
> **Note:** Monitor directory services interactions by breakglass accounts.  
```kql
AuditLogs
| where tostring(InitiatedBy.user.userPrincipalName) contains "@example.onmicrosoft.com"
| where TimeGenerated >= datetime(2030-MM-DD) and TimeGenerated < datetime(2030-MM-DD)
| project TimeGenerated, ActivityDisplayName, InitiatedByUserPrincipalName = tostring(InitiatedBy.user.userPrincipalName), ActionDetails = tostring(parse_json(TargetResources)), AADOperationType, Resource, TargetDisplayName = tostring(parse_json(TargetResources)[0].displayName), Result
| order by TimeGenerated desc
```

## Role Analysis  
> **Note:** Analyze role membership changes.  
```kql
AuditLogs
| where OperationName == "Add member to role" or OperationName == "Remove member from role"
| where TimeGenerated >= datetime(2030-MM-DD) and TimeGenerated < datetime(2030-MM-DD)
| project TimeGenerated, OperationName, InitiatedByUser = tostring(parse_json(InitiatedBy).user.displayName), TargetUser = tostring(parse_json(TargetResources)[0].displayName), TargetUserPrincipalName = tostring(parse_json(TargetResources)[0].userPrincipalName), RoleDisplayName = tostring(parse_json(TargetResources)[0].modifiedProperties[0].displayName), RoleValue = tostring(parse_json(TargetResources)[0].modifiedProperties[0].newValue)
| sort by TimeGenerated desc
```