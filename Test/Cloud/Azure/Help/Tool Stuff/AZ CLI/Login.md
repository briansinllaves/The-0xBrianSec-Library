- PowerShell installation and Azure CLI connection:
    - PowerShell command: `Install-Module -ne Az -Repository PSGallery -Force`
    - PowerShell command: `connect-AzAccount`
    - Use Azure CLI in Windows Terminal
    
- Login to Azure CLI using Personal Access Token (PAT):
    
    ```
    az devops login --organization=https://dev.azure.com/ABCD-zlop1-SadDadZone token  
    ```


- Login to Azure CLI using Service Principal ne (SPN):
    ```
    az login --service-principal -u <client-id> -p="<password secret>" --tenant <id>  
    ```


Example command:
    
```
az login --service-principal -u c50c4fcc-2676-42d4-a7b0 -p /u7Lyk?BL --tenant 513294a
    
```   
