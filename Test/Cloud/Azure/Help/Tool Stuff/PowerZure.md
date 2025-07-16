```
Get-ExecutionPolicy -List  
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine  
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser  

PS C:\Users\Tester\Desktop\MyToolKit\Azure> Import-Module .\PowerZure-master\PowerZure-master\PowerZure.psm1


```

 more focused on leveraging permissions and exploring Azure resources. However, you can use several PowerZure commands to explore different areas where credentials might be found, such as Azure Key Vaults or service principals.

```
Get-AzureTarget
Get-AzureIntuneScript
Get-AzureManagedIdentity
Get-AzureRunAsAccount
Get-AzAdApplication > AzAdApplication.txt

?

"Show-AzureKeyVaultContent -All
Show-AzureStorageContent -All -Verbose
Get-AzureTarget"
Get-AzContainerRegistry -SubscriptionId "012ae8b12"
Connect-AzContainerRegistry -ne "us00"
Get-AzKeyVault -SubscriptionId "012a59-3179-4bb12"

```

