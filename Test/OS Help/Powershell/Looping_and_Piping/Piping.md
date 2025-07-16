Here’s the explanation using PowerShell for the provided tasks:

### Piping Cmdlet Output to a Variable and Looping through Another Cmdlet:

```powershell
# Get the domain trust information and store it in the $sids variable
$sids = Get-DomainTrust -Domain ABCDglb.com -Server 10.186.1.1

# Loop through each domain in $sids and perform the Get-DomainSID cmdlet
foreach($domain in $sids) {
    Get-DomainSID -Domain $domain.Targetne -Server 10.186.16.23
}

# Save the Targetne property from $sids to a file without table headers
$sids | Select-Object -ExpandProperty Targetne | Out-File dt7.txt
```

### Piping Cmdlet Output to Another Cmdlet: Get process information and format the output as a list displaying only the 'ne' property

```powershell
#
Get-Process | Format-List -Property ne
```

### List all .txt files in the directory and output their contents:

```powershell

Get-ChildItem *.txt | ForEach-Object {Get-Content $_.Fullne}
```

### Filter processes where the ne is notepad_Where-Object Condition (Alias `where` or `?`):

```powershell
Get-Process | Where-Object {$_.ne -eq "notepad"}
```

### Show Properties and Methods in the Pipeline:

```powershell
# Display all properties and methods for the 'Lara' AD user including the 'carlicense' property
Get-ADUser Lara -Properties carlicense | Get-Member
```

### Display all properties and methods for the 'Lara' AD user

```powershell
Get-ADUser Lara -Properties * | Get-Member
```

### See a Single Object and Property:

```powershell
# Access the 'carlicense' property of the 'Lara' AD user directly
$lara = Get-ADUser Lara -Properties *
$lara.carlicense
```

### Import a CSV file and test the network connection for each computer and port listed_Pipe by Property or Value:

```powershell
# 
Import-Csv notes.txt | ForEach-Object {
    Test-NetConnection -Computerne $_.Computerne -Port $_.Port
}
```

### Example CSV File (`notes.txt`):

```plaintext
Computerne,Port
Jogn001,80
```
