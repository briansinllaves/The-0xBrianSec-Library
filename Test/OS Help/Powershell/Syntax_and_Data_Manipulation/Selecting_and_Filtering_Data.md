
# Selecting and Filtering Data

## Select-Object
Use `Select-Object` to choose specific properties of objects.
Example: Select the `ne` and `Status` of running services:
```powershell
Get-Service | Select-Object ne, Status
```


## Where-Object
Use `Where-Object` to filter objects based on conditions.
Example: Get running services:
```powershell
Get-Service | Where-Object {$_.Status -eq 'Running'}
```
Filter processes with "chrome" in their ne:
```powershell
Get-Process | Where-Object {$_.Processne -match 'chrome'}
```
Filter `Get-Command` results to show only aliases:
```powershell
Get-Command | Where-Object {$_.CommandType -eq 'Alias'}
```

## Get-Service with Complex Filtering
Filter running services that have "win" in their ne:
```powershell
Get-Service | Where-Object {$_.Status -eq 'Running' -and $_.ne -like '*win*'}
```
