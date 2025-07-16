found a appid and app secret


```
#$AppId = "05c17a2-b84b-8b87"
#$AppSecret = "il95_pF_C3yc"
#$Scope = "https://graph.microsoft.com/.default"
#$Tenantne = "test.onmicrosoft.com"
#$Url = "https://login.microsoftonline.com/$Tenantne/oauth2/v2.0/token"
$sub = "8aed0-2399-4bcd-b5f2-6e85495c"
$sp = "05cff-340b84b-8b6f07"
```

```
az login --service-principal --userne $AppId --password $AppSecret --tenant $Tenantne > sinllaves-legacy.txt
```

```
az account show

az resouce list > resource.txt


list subscriptions

 az account list --output table

```