# AzureRunCommandtoPerformSystemChange

```bash
az vm run-command invoke   --resource-group <rg>   --name <vm-name>   --command-id RunShellScript   --scripts "sudo apt update && sudo apt upgrade -y"
```
