### Bash Script for Credential Checking with SQL Instances:

```bash
#!/bin/bash

# Function to handle errors
error_exit() {
    echo "$1" 1>&2
    exit 1
}

# Retrieve SQL Instances from the specified domain (simulated with a placeholder command)
instances=$(some_sql_instance_discovery_command --domain-controller 1.1.1.14 2>&1) || error_exit "Error: Failed to retrieve SQL Instances."

echo "Retrieved SQL Instances from specified domain."

# Check if instances variable is empty
if [ -z "$instances" ]; then
    error_exit "Error: No instances retrieved."
fi

# Filter instances for 'aur' in the ne
aur_instances=$(echo "$instances" | grep 'aur')

echo "Filtered instances for 'aur' in the ne."

# Check if aurInstances variable is empty
if [ -z "$aur_instances" ]; then
    error_exit "Error: No instances containing 'aur' in the ne found."
fi

# Credentials for the attempts
declare -A credentials
credentials=(
    ["aurasysadmin"]="ps3]qcMr-cd~pnMNg3X[z2wEyuuTyPur_QJd+qsE9vEr[@!9TCAbzY_A5jnT-b33j82FfCexjP$!W]s_x6aY(W2FhzNkB*(venAqw4HW+7cXX2w9TEZuU-S]|S-qu*q"
    ["aurasysadmin2"]="mX(1_nZRmyS3a{8MabVUbktAEJgBa~FKqGFN6yK9ANv_uKzpXp}ynXtQMUYmQkw7FzZaTu]fCAxW0NqRpweBrRGSU[uh5PzyDSDLwmDw|dEKzh4puR2BttgHj!gmj)y"
)

echo "Credentials prepared for connection attempts."

# Iterate through filtered instances and credentials
while read -r instance; do
    for userne in "${!credentials[@]}"; do
        password="${credentials[$userne]}"

        if [ -z "$userne" ] || [ -z "$password" ]; then
            echo "Error: Userne or Password is null or empty."
            continue
        fi

        echo "Attempting connection to $instance with $userne."

        # Simulate a connection attempt (replace with actual SQL connection logic)
        if some_sql_connection_command --instance "$instance" --userne "$userne" --password "$password"; then
            echo "Successfully connected to $instance with $userne."
            some_sql_disconnect_command --instance "$instance"
        else
            echo "Error: Failed to connect to $instance with $userne."
        fi
    done
done <<< "$aur_instances"
```

### Explanation:

1. **Error Handling**:
   - `error_exit()` is a function to handle errors and exit the script with an error message.

2. **Retrieving SQL Instances**:
   - This part is simulated with a placeholder command (`some_sql_instance_discovery_command`). Replace it with the actual command you use to discover SQL instances.

3. **Filtering Instances**:
   - `grep 'aur'` is used to filter instances that contain 'aur' in their ne.

4. **Credentials**:
   - A Bash associative array `credentials` is used to store the userne-password pairs.

5. **Iterating Through Instances and Credentials**:
   - The script loops through each instance and tries to connect using each set of credentials.
   - Replace `some_sql_connection_command` and `some_sql_disconnect_command` with the actual commands used to connect and disconnect from SQL instances.

### Notes:
- This script is a basic structure; you will need to replace placeholder commands with the actual tools/commands you are using in your environment.
- The SQL connection and disconnection logic should be adapted to your specific SQL client and authentication method.