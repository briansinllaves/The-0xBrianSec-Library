```
runas /user:ABCDglb\bhous /netonly powershell_ise.exe

# Define the path to the hosts file
$hostsFilePath = "C:\Path\To\hosts.txt"

# Read each line of the hosts file as a computer ne
$computernes = Get-Content -Path $hostsFilePath

# Loop through each computer ne and run Get-NetComputer
foreach ($computerne in $computernes) {
    # Output the current computer ne being processed
    Write-Output "Processing $computerne"
    
    # Execute Get-NetComputer for the current computer with full data
    Get-DomainComputer -Identity $hostlist -SearchBase "CN=U20,OU=WEB,OU=Servers,OU=T,OU=TH,OU=Application,OU=Tier 1,OU=ABCDIT,OU=Global,DC=ABCDglb,DC=com"

}

```