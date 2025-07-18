found a appid and app secret


```
#$AppId = "087"
#$AppSecret = "yc"
#$Scope = "https://graph.microsoft.com/.default"
#$Tenantne = "test.onmicrosoft.com"
#$Url = "https://login.microsoftonline.com/$Tenantne/oauth2/v2.0/token"
$sub = "8"
$sp = "0"
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