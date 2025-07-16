take list of usernes and passwords and run in a script  to scan domain for disabled and active users. - Password assessment



-----------------------------------------------------------------
```
cmd > runas /netonly /user:DOMAIN\user powershell.exe
```

new window (powershell)

```
nslookup domain
import-module powerview recon module or . .\powerview.ps1
# Step 1: Read the list of users from the text file
$users = Get-Content "C:\Users\briantest\Desktop\glbext-users.txt"

# Step 2: Initialize arrays to store disabled and active users
$disabled = @()
$current = @()

# Step 3: Iterate over each user in the list
foreach ($u in $users) {
    
    # Step 4: Get information about the user from the specified domain and server
    $i = Get-DomainUser -Domain $domainne -Identity $u -Verbose
    
    # Step 5: Check if the user account is disabled
    if (-not ([string]::IsNullOrEmpty($i)) -and $i.useraccountcontrol.ToString() -like "*ACCOUNTDISABLE*") {
        
        # If the user account is disabled, add the userne to the $disabled array
        $disabled += $u
    } 
    else {
        
        # If the user account is not disabled, add the userne to the $current array
        $current += $u
    }
}

# Step 6: Output the results to text files
$current | Out-File "n-currentuser.txt"
$disabled | Out-File "n-disableduser.txt"

# Step 7: Display the content of the files
type "n-currentuser.txt"
type "n-disableduser.txt"

```

