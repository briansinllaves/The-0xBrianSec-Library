

### AWS Configuration Commands
```shell
aws configure set region $region
aws configure set aws_secret_access_key $secretKey
aws configure set aws_access_key_id $accessKey
```

### Reading `awscreds.txt` and Storing Key Pair Values
1. **Read contents of `awscreds.txt`**:
   - If line contains "accesskey", store the key pair value in variable `$accesskey`.
   - If line contains "secretKey", store the key pair value in variable `$secretkey`.
   - If line contains "region", store the key pair value in variable `$region`.

### AWS Configuration Commands After Storing Values
```shell
aws configure set aws_access_key_id $accessKey
aws configure set aws_secret_access_key $secretKey
aws configure set region $region
```

### List S3 Buckets and Output
```shell
aws s3 ls | ForEach-Object { $_.Split(' ')[-1] } | Out-File -FilePath "$accesskey.s3buckets.txt"
```

### Error Handling
- If there is an error when trying to connect to AWS, report the `$accesskey` and the error message output to `notauthenticated.txt`, and then continue.

### Ignore Duplicate Key Values
- Ignore if the next line has the same access key value as the previous.
- Ignore if the next line has the same region key value as the previous.
- Ignore if the next line has the same secret key value as the previous.
- Continue reading and trying to connect.

### PowerShell Module Installation and Usage
```powershell
Install-Module -ne AWSPowerShell.NetCore
Import-Module -ne AWSPowerShell.NetCore
Set-AWSCredential -AccessKey $accessKey -SecretKey $secretKey
Get-IAMUser | Out-File -FilePath "$accessKey.IAMUser.txt"
```

This organized structure separates the different sections for better readability and understanding.