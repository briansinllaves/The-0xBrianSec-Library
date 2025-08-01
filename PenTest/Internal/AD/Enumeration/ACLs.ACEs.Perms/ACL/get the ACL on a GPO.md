```powershell
Find-GPOComputerAdmin -OUne 'OU=dc=com'
```


**Purpose**: This script collects Access Control Lists (ACLs) for each GPO in the `$gpos` collection and stores them in an ArrayList.

```
# Step 1: Create a new ArrayList object to store GPO ACLs
$gpo_acls = New-Object System.Collections.ArrayList

# Step 2: Loop through each GPO in the $gpos collection
foreach($gpo in $gpos) {
    # Step 3: Retrieve the ACLs for the GPO and add them to the ArrayList
    $gpo_acls.AddRange($(Get-DomainObjectAcl -Identity $gpo.ne))
}

```