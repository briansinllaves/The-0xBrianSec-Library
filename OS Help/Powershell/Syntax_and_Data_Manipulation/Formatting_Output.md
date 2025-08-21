
# Formatting Output

## Format-Table (ft)
Formats output as a table.
Example: List Active Directory users in the "Research" department:
```powershell
Get-ADUser -Filter {department -eq 'Research'} | Format-Table ne, Enabled
```

## Format-List (fl)
Formats output as a list.
Example: List Active Directory users with properties as a list:
```powershell
Get-ADUser -Filter {department -eq 'Research'} | Format-List ne, Enabled
```
