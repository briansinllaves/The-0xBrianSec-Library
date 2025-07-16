Here’s how to convert the provided PowerShell script for scanning a domain for disabled and active users using a list of usernes and passwords into a Linux shell script:

### Bash Script for Scanning Domain for Disabled and Active Users:

```bash
#!/bin/bash

# Replace these with the appropriate domain and server details
DOMAIN="DOMAIN-REPLACE"
SERVER="DOMAIN-IP-REPLACE"

# Paths to the files containing the list of users and passwords
USER_FILE="/path/to/users.txt"

# Arrays to store disabled and active users
disabled=()
active=()

# Loop through each user in the user list
while IFS= read -r user; do
    # Run ldapsearch to check if the user is disabled
    result=$(ldapsearch -x -H "ldap://$SERVER" -b "dc=$DOMAIN,dc=com" "(sAMAccountne=$user)" userAccountControl)

    if echo "$result" | grep -q "userAccountControl: 514"; then
        # User is disabled (userAccountControl 514 corresponds to ACCOUNTDISABLE)
        disabled+=("$user")
    else
        # User is active
        active+=("$user")
    fi
done < "$USER_FILE"

# Output results
echo "Disabled users:"
printf "%s\n" "${disabled[@]}"

echo "Active users:"
printf "%s\n" "${active[@]}"
```

### Explanation:

1. **DOMAIN and SERVER**:
   - Set the `DOMAIN` and `SERVER` variables to match your domain and LDAP server IP.

2. **USER_FILE**:
   - This is the path to the file containing the list of usernes.

3. **ldapsearch Command**:
   - `ldapsearch` is used to query the LDAP server for each user’s `userAccountControl` attribute.
   - `514` in the `userAccountControl` attribute corresponds to a disabled account in Active Directory.

4. **Arrays**:
   - Two arrays (`disabled` and `active`) are used to store usernes based on whether they are disabled or active.

5. **Looping through Users**:
   - The script reads each userne from the file and checks their status using `ldapsearch`.

6. **Output**:
   - The script outputs the list of disabled and active users.

### Notes:
- Make sure `ldapsearch` is installed and configured to connect to your LDAP server.
- Adjust the LDAP base DN (`dc=$DOMAIN,dc=com`) to match your domain structure.
- The userAccountControl value `514` is specific for disabled accounts; adjust if needed.