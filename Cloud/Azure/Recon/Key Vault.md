
# Look at values Contents of Vault

```
$tenant_id = '5fa'
$client_secret = 'su'
$client_id = 'a2'

az login --service-principal -u $client_id -p $client_secret --tenant $tenant_id --allow-no-subscriptions


az keyvault secret list --vault-ne "risk-atlas-key-vault-stg"

$keyVaultEntries = (az keyvault secret list --vault-ne "risk-atlas-key-vault-uat" | ConvertFrom-Json) | Select-Object id, ne
    
Write-Host "| key | secret value |"
Write-Host "| --- | ------------ |"
foreach($entry in $keyVaultEntries)
{
    $secretValue = (az keyvault secret show --id $entry.id | ConvertFrom-Json) | Select-Object ne, value
    Write-Host "| " $secretValue.ne " | " $secretValue.value " |"
}
```







