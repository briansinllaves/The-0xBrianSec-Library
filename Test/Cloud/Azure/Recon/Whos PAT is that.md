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
{ "authenticatedUser": { "id": "79de1729-b775-653a-ac7c-3937c662999d", "descriptor": "Microsoft.IdentityModel.Claims.ClaimsIdentity;513294a0-3e20-41b2-a970-6d30bf1546fa\\tom.ford@ABCD.com", "subjectDescriptor": "aad.NzlkZTE3MjktYjc3NS03NTNhLWFjN2MtMzkzN2M2NjI5OTlk", "providerDisplayne": "Forrest Tiffany", "isActive": true, "properties": { "Account": { "$type": "System.String", "$value": "tom.ford@ABCD.com" } }, "resourceVersion": 2, "metaTypeId": 0 }, "authorizedUser": { "id": "79de1729-b775-653a-ac7c-3937c662999d", "descriptor": "Microsoft.IdentityModel.Claims.ClaimsIdentity;513294a0-3e20-41b2-a970-6d30bf1546fa\\tom.ford@ABCD.com", "subjectDescriptor": "aad.NzlkZTE3MjktYjc3NS03NTNhLWFjN2MtMzkzN2M2NjI5OTlk", "providerDisplayne": "Forrest Tiffany", "isActive": true, "properties": { "Account": { "$type": "System.String", "$value": "tom.ford@ABCD.com" } }, "resourceVersion": 2, "metaTypeId": 0 }, "instanceId": "1bc72ea6-3169-407c-aaf2-f88eded53215", "deploymentId": "371dc223-5e58-9481-da2c-e75ac4f20939", "deploymentType": "hosted", "locationServiceData": { "serviceOwner": "00025394-6065-48ca-87d9-7f5672854ef7", "defaultAccessMappingMoniker": "PublicAccessMapping", "lastChangeId": 259878979, "lastChangeId64": 259878979 } }
```