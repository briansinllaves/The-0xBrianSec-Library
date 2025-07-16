do a search in sublime
copy out the find results into a text

```# Path to the credentials file  
$credentialsFilePath = "awscredstestrun.txt"  
# Path to the tried access keys file  
$triedAccessKeysFilePath = "TriedAccessKeys.txt"  
  
# Create an empty array to store the tried access keys  
$triedAccessKeys = @()  
  
# Read and process each line from the credentials file  
Get-Content $credentialsFilePath | ForEach-Object {  
    # Extract credentials from the file based on the JSON-like structure  
    if ($_ -match '"accessKey": "([^"]+)"') { $accessKey = $Matches[1] }  
    elseif ($_ -match '"secretKey": "([^"]+)"') { $secretKey = $Matches[1] }  
    elseif ($_ -match '"region": "([^"]+)"') {  
        $region = $Matches[1]  
  
        # Configure AWS CLI with the current set of credentials  
        Set-AWSCredential -AccessKey $accessKey -SecretKey $secretKey   
  
        # Display the access key being tested  
        Write-Host "Testing Access Key: $accessKey"  
  
        # Add the access key to the array of tried access keys  
        $triedAccessKeys += $accessKey  
  
        # Attempt to list iamuser  
        $iamUser = Get-IAMUser  
        if ($iamUser) {  
            $iamUser | Out-File -FilePath "$($accessKey).IAMUser.txt"  
        }  
    }  
}  
  
# Write the tried access keys to the file  
$triedAccessKeys | Out-File -FilePath $triedAccessKeysFilePath  


```