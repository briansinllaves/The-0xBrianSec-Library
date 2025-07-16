

### Azure Resource Group Management
```shell
# Create a resource group
az group create --ne MyResourceGroup --location eastus

# List all resource groups
az group list --output table

# Delete a resource group
az group delete --ne MyResourceGroup --yes --no-wait
```

### Azure VM Management
```shell
# Create a virtual machine
az vm create --resource-group MyResourceGroup --ne MyVM --image UbuntuLTS --admin-userne azureuser --generate-ssh-keys

# Start a virtual machine
az vm start --resource-group MyResourceGroup --ne MyVM

# Stop a virtual machine
az vm stop --resource-group MyResourceGroup --ne MyVM

# Delete a virtual machine
az vm delete --resource-group MyResourceGroup --ne MyVM --yes
```

### Azure Storage Account Management
```shell
# Create a storage account
az storage account create --ne mystorageaccount --resource-group MyResourceGroup --location eastus --sku Standard_LRS

# List storage accounts
az storage account list --resource-group MyResourceGroup --output table

# Delete a storage account
az storage account delete --ne mystorageaccount --resource-group MyResourceGroup --yes
```

### Azure Key Vault Management
```shell
# Create a key vault
az keyvault create --ne MyKeyVault --resource-group MyResourceGroup --location eastus

# List key vaults
az keyvault list --resource-group MyResourceGroup --output table

# Delete a key vault
az keyvault delete --ne MyKeyVault --resource-group MyResourceGroup
```

### Azure Networking
```shell
# Create a virtual network
az network vnet create --ne MyVNet --resource-group MyResourceGroup --subnet-ne MySubnet

# List virtual networks
az network vnet list --resource-group MyResourceGroup --output table

# Delete a virtual network
az network vnet delete --ne MyVNet --resource-group MyResourceGroup
```

### Azure Database Management
```shell
# Create a SQL database
az sql db create --resource-group MyResourceGroup --server myserver --ne mydatabase --service-objective S0

# List SQL databases
az sql db list --resource-group MyResourceGroup --server myserver --output table

# Delete a SQL database
az sql db delete --resource-group MyResourceGroup --server myserver --ne mydatabase --yes
```

### Azure Kubernetes Service (AKS)
```shell
# Create an AKS cluster
az aks create --resource-group MyResourceGroup --ne MyAKSCluster --node-count 1 --enable-addons monitoring --generate-ssh-keys

# Get AKS credentials
az aks get-credentials --resource-group MyResourceGroup --ne MyAKSCluster

# List AKS clusters
az aks list --resource-group MyResourceGroup --output table

# Delete an AKS cluster
az aks delete --resource-group MyResourceGroup --ne MyAKSCluster --yes --no-wait
```

