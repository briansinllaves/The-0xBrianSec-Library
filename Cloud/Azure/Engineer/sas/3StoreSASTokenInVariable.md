# 3StoreSASTokenInVariable

```bash
SAS_TOKEN=$(az storage container generate-sas   --account-name <storage-account>   --name <container-name>   --permissions rwl   --expiry 2025-12-31T23:59Z   --output tsv)
```
