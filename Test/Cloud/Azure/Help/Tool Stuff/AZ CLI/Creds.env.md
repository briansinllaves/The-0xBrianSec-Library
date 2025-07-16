```
Az cli

Use the Client ID and KeyVault Secret to authenticate via Azure CLI

Key vault notes

$tenant_id = '5-3e20-41b2-a6fa'

$client_secret = 'XjF8Q~teqY3csu'

$client_id = 'a2712d-eb4b-4d-8ab7-03f9c462'

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