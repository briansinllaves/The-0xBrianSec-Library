
Using Get-DomainObject

```
# Define the SID
$sid = 'S-1-5-21-3661641031-396-1577785'

# Search for the object by SID
$adObject = $sid | Get-DomainObject -Properties distinguishedne

# Display the Distinguishedne of the object
$adObject.Distinguishedne

```




Using Get-ADObject

```
# Define the SID
$sid = 'S-1-5-21-36616431-39061
# Search for the object by SID, including deleted objects
$adObject = Get-ADObject –IncludeDeletedObjects -Identity $sid -Properties ne, ObjectClass -Server G-5.ABCDglb.com

# Display the ne, ObjectClass, and Domain of the object
$adObject | Select-Object ne, ObjectClass, @{ne="Domain";Expression={$adObject.Server}}

```
