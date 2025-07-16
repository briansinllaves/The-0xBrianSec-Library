
```
Get-RecursiveGroupMembers -user "brian" -domain "domain.com" -server "10.4.6.2"

- After identifying those groups, it will recursively run `Get-RecursiveGroupMembers` for each group. This means, if `"brian"` is in `"GroupA"`, it will then look for groups that `"GroupA"` is a member of.
- This recursion continues until all nested memberships are found and listed.

```

```
function Get-RecursiveGroupMembers {
    param (
        [string]$user,
        [string]$domain,
        [string]$server
    )

    # Get all groups where the user is a member
    $groups = Get-DomainGroup -MemberIdentity $user -Domain $domain -Server $server | Select-Object -ExpandProperty samaccountne

    foreach ($group in $groups) {
        Write-Output $group
        # Recursively get members of each group
        Get-RecursiveGroupMembers -user $group -domain $domain -server $server
    }
}

# Call the function with the initial user
Get-RecursiveGroupMembers -user "brian" -domain "domain.com" -server "10.4.6.2"

```