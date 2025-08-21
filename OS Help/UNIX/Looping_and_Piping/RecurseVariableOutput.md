### Bash Script for Recursively Getting Group Members:

```bash
#!/bin/bash

# Function to recursively get group members
get_recursive_group_members() {
    local user=$1
    local domain=$2
    local server=$3

    # Get all groups where the user is a member
    groups=$(ldapsearch -x -H "ldap://$server" -b "dc=$domain,dc=com" "(memberUid=$user)" | grep 'cn: ' | awk '{print $2}')

    for group in $groups; do
        echo "$group"
        # Recursively get members of each group
        get_recursive_group_members "$group" "$domain" "$server"
    done
}

# Call the function with the initial user
get_recursive_group_members "brian" "domain" "10.4.6.2"
```

### Explanation:

1. **ldapsearch Command**:
   - `ldapsearch` is used to search the LDAP directory for groups where the user is a member.
   - The `-x` option specifies simple authentication.
   - `-H "ldap://$server"` defines the LDAP server.
   - `-b "dc=$domain,dc=com"` specifies the base search DN.
   - `"(memberUid=$user)"` is the filter to find groups where the user is a member.
   - `grep 'cn: '` extracts the `cn` (common ne) of the groups.
   - `awk '{print $2}'` extracts just the group ne from the line.

2. **Recursion**:
   - The function `get_recursive_group_members` calls itself to handle nested group memberships.

3. **Function Call**:
   - The function is called with the initial user "brian" and the corresponding domain and server.

### Notes:
- Ensure that the `ldapsearch` command is available and correctly configured to access your LDAP server.
- Replace `domain` and `server` with the appropriate values for your environment.
- You may need to adjust the LDAP filter and base DN (`dc=$domain,dc=com`) depending on your specific LDAP schema.