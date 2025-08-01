```
import-module powerdevops.ps1
PS C:\Users\bhous\Desktop\MyToolKit\Azure\cloud_tools\PowerUpDevops> Devops-Login -Organization ABCD-zlop1-SadDadZone -PAT 7zh6clwsfbr7mmvrx6yepts47w54fmyaybfuaphagqygukoqba4a
```




check who's PAT you are using by making a GET request with the PAT to Azure DevOps REST API

```
Invoke-WebRequest -Uri 'https://dev.azure.com/ABCD-zlop1-SadDadZone/_apis/connectionData' -Headers $Headers
```

Example output
```
{ "authenticatedUser": { "id": "79ded", "descriptor": "Microsoft.IdentityModel.Claims.ClaimsIdentity;51\\tom.ford@ABCD.com", "subjectDescriptor": "alk", "providerDisplayne": "Forrest Tiffany", "isActive": true, "properties": { "Account": { "$type": "System.String", "$value": "tom.ford@ABCD.com" } }, "resourceVersion": 2, "metaTypeId": 0 }, "authorizedUser": { "id": "", "descriptor": "9 } }
```