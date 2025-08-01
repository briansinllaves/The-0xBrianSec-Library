# InvestigationReason

Document reasons for incident investigation or resource changes.

Example:
```bash
az monitor activity-log list --max-events 5 --query "[].{caller:caller, operationName:operationName.value}" -o table
```
