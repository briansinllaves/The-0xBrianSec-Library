
To list Azure AD applications and their credentials (you might need permissions to view these details):

```
Get-AzADApplication | ForEach-Object {
    $appId = $_.ApplicationId
    Get-AzADAppCredential -ObjectId $appId
    }
```

To list service principals and their credentials
```
Get-AzADServicePrincipal | ForEach-Object {
    $spId = $_.Id
    Get-AzADSpCredential -ObjectId $spId
}
```