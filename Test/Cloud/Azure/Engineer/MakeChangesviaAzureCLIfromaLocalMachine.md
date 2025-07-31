# MakeChangesviaAzureCLIfromaLocalMachine

```bash
az group update --name <group-name> --set tags.Env=Production
az vm update --name <vm-name> --resource-group <rg> --set tags.PatchWindow="Sunday"
```
