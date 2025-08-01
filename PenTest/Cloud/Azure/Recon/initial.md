### Azure Initial Recon

#### Tools:
- AzureHound
- AADInternals
- AzCLI
- PowerZure

#### Command for AzureHound:
```bash
# Run AzureHound to list information using a refresh token for a specific tenant
./azurehound -r "0.RefreshToken" list --tenant "admin.ABCD.com" -o output.json
```

#### Tenant Information:
- Gather detailed tenant information using the AzureHound command above.
- Check tenant information with AzCLI:
  ```bash
  az account show --output table
  ```

#### User Enumeration:
- Enumerate users and their details with AzureHound.
- Use AzCLI for user enumeration:
  ```bash
  az ad user list --output table
  ```

#### Azure Services:
- Identify and enumerate various Azure services in use with AzureHound.

#### Open Storage:
- Check for publicly accessible storage accounts with AzureHound.
- Use AzCLI to list storage accounts:
  ```bash
  az storage account list --output table
  ```

#### SAS URL:
- Look for Shared Access Signature (SAS) URLs for potential storage access.

#### Command for AADInternals:
```powershell
# Query all information of an Azure tenant
Invoke-AADIntReconAsOutsider -Domainne ABCD.onmicrosoft.com | Format-Table
```

#### NSG (Network Security Groups):
- Review NSGs for configuration and potential misconfigurations with AzCLI:
  ```bash
  az network nsg list --output table
  ```

#### AzFirewall:
- Investigate Azure Firewall configurations and rules.
- List Azure Firewalls with AzCLI:
  ```bash
  az network firewall list --output table
  ```

#### Virtual Appliances:
- Identify and review virtual appliances within the Azure environment.

#### Routing Tables:
- Examine routing tables for insights and potential vulnerabilities with AzCLI:
  ```bash
  az network route-table list --output table
  ```

#### List VNETs with Service Endpoints:
- Identify Virtual Networks (VNETs) that have service endpoints configured.
- Use AzCLI to list VNETs:
  ```bash
  az network vnet list --output table
  ```

#### Additional Commands:

- **List Azure Subscriptions**:
  ```bash
  az account list --output table
  ```

- **List Resource Groups**:
  ```bash
  az group list --output table
  ```

- **List All Resources**:
  ```bash
  az resource list --output table
  ```

- **List Azure SQL Databases**:
  ```bash
  az sql db list --output table
  ```

- **List Key Vaults**:
  ```bash
  az keyvault list --output table
  ```

- **List App Services**:
  ```bash
  az webapp list --output table
  ```