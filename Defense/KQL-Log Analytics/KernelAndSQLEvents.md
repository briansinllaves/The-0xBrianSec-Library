### Kernel Event IDs (13, 37, 41, 201)
```kql
Event
| where EventID in (13, 37, 41, 201)
| project TimeGenerated, Computer, EventID, RenderedDescription
| sort by TimeGenerated desc
```
<!--- Monitors firmware throttling, crashes, and hardware failures. -->

### SQL Server Event Monitoring
```kql
Event
| where EventID in (18456, 17137, 17142, 17145, 18264, 18265, 18270, 208, 12288, 12289)
| project TimeGenerated, Computer, EventID, RenderedDescription
| sort by TimeGenerated desc
```
<!--- Includes login failures, service status, backup/restore, and job status. -->

