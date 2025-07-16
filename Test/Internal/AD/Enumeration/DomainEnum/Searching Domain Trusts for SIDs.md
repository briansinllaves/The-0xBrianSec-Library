
```powershell
# Step 1: Retrieve domain trust information from a specific domain and server
$sids = Get-DomainTrust -Domain ABCDglb.com -Server 1.1.1.23;

# Step 2: Loop through each domain trust retrieved in $sids
foreach($domain in $sids){
    # Step 3: Retrieve the SID for each trusted domain and output the result
    Get-DomainSID -Domain $domain.Targetne -Server 1.6.6.3
}

```

- **Purpose**: This script retrieves domain trust information and attempts to retrieve SIDs from each trusted domain.