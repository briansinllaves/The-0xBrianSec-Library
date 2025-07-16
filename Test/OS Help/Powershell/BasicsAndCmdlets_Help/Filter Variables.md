```
$filteredInstances = $instances | Where-Object { $_.Instance -like '*aur*' -or $_.Instance -match 'aur' -or $_.Instance -contains 'aur'}
```