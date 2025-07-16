```
$b64PAT = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("")) $headers = @{Authorization = "Basic $b64PAT" 'Content-Type' = "application/json" } Invoke-WebRequest -Uri ""[https://dev.azure.com/test-zlop1-SadDadZone/dad-cloud/_apis/git/repositories?includeLinks=True&includeAllUrls=True&includeHidden=True&api-version=7.1-preview.1](https://dev.azure.com/test-zlop1-SadDadZone/dad-cloud/_apis/git/repositories?includeLinks=True&includeAllUrls=True&includeHidden=True&api-version=7.1-preview.1)"" -Headers $headers"
```



