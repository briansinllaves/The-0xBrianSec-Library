
# Basic Cmdlets and Output Redirection

## Output Redirection to a File
```powershell
cmdlet | Out-File werew.txt
```
Example: Save the output of `Get-Process` to a file:
```powershell
Get-Process | Out-File processes.txt
```

## Export to CSV
```powershell
cmdlet | Export-Csv mark.csv -NoTypeInformation
```
Example: Export services to a CSV file:
```powershell
Get-Service | Export-Csv services.csv -NoTypeInformation
```
