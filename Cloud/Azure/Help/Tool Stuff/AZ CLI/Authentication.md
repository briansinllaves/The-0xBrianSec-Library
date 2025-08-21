### Authenticate via Azure CLI Using Client ID and KeyVault Secret

#### Set the Tenant ID, Client Secret, and Client ID Variables
```shell
tenant_id=<your-tenant-id>
client_secret=<your-client-secret>
client_id=<your-client-id>
```

#### Login with Service Principal
```shell
az login --service-principal -u $client_id -p $client_secret --tenant $tenant_id --allow-no-subscriptions
```

#### List Secrets in the KeyVault
```shell
az keyvault secret list --vault-ne "risk-atlas-key-vault-uat"
```

#### Retrieve Secret Values
```shell
az keyvault secret show --id <secret-id>
```