```
$instances = Get-SQLInstanceDomain -Verbose -DomainController 1.1.1.1
$instances[0]
$instances.  (print one field from object output) 

$instance.count

$filteredInstances = $instances | Where-Object { $_.Instance -like '*aur*' -or $_.Instance -match 'aur' -or $_.Instance -contains 'aur'}

$filteredInstances[0]   is var with array, it gets first object of list of output

$pass = 'inhere'

$filteredInstances | Get-SQLConnectionTestThreaded -Verbose -Threads 10 -userne $admin -password $pass
```
