# File Storage and Shares:

- [ ]  Verify if blob and files can be shared without a SAS key.
  - Test: Attempt to access a shared blob or file URL without providing a SAS key.
```powershell
az storage container show --account-ne <StorageAccountne> --ne <Containerne> --query "properties.publicAccess"

```


   - Test: Check for public access level settings on storage containers to ensure they are not inadvertently exposed.   
``` azure cli
az storage container show --account-ne <StorageAccountne> --ne <Containerne> --query "properties.publicAccess"

```

- [ ]  Check if the URL itself serves as the authentication mechanism for accessing the stored content.
    - Test: Access the URL directly in a browser or using a tool like cURL or PowerShell's `Invoke-RestMethod`.
    
    - Test: Verify if network-level restrictions (like IP whitelisting) are in place for accessing the URL.
```powerzure

Get-PZNetworkRule -ResourceGroupne <ResourceGroupne> -StorageAccountne <StorageAccountne>
```

- [ ]  Confirm if Storage Explorer can be used without the key expiring.
    - Test: Use Storage Explorer to access the storage account and perform operations on the files or blobs.
    - Test: Validate the policy enforcement for key rotation and expiry to ensure long-term access requires updated authentication.
    
```PowerShell/Azure CLI

az storage account keys list --account-ne <StorageAccountne> --query "[].{Keyne:keyne, Permissions:permissions, ExpirationDate:expirationTime}"

```


- [ ]  Examine the URL for any expiration date.
    - Test: Inspect the URL properties or metadata to check for an expiration date.
    - Test: Attempt to modify the URL parameters to bypass any potential expiration limitations.
```Manual
# This test involves manually altering the URL parameters in a browser or with a tool like cURL to test access.
```


# Permissions and Access:

- [ ]  Check the permissions for read and write operations.
    - Test: Attempt to read and write files or blobs using different access levels (e.g., read-only, write-only, read-write).
    - Test: Evaluate the effective permissions of shared access signatures (SAS) to ensure they adhere to the principle of least privilege.
```azure cli
az storage blob generate-sas --account-ne <StorageAccountne> --container-ne <Containerne> --ne <Blobne> --permissions rw --expiry <YYYY-MM-DD> --output tsv
```

- [ ]  Obtain a Service Principal ne (SPN) to bypass multi-factor authentication (MFA).
    - Test: Create an SPN using Azure CLI or AADInternals and verify if it can authenticate without MFA.
    
    - Test: Analyze the audit logs for SPN activities.
```Azure CLI
az monitor activity-log list --resource-group <ResourceGroupne> --query "[?authorization.scope contains '<SPNId>']"

```

# Accessible Machines and Lateral Movement:

- [ ]  Identify which machines are accessible within the environment.
    - Test: Use Azure CLI, PowerShell, AzureHound to list and identify the machines or VMs in the environment.


- [ ]  Assess the capabilities of the SPN to determine potential lateral movement opportunities.
    - Test: User AADInternals or Azure CLI to check the roles and permissions assigned to the SPN.

	
    - Test: Attempt to escalate privileges using the SPN to uncover any potential security weaknesses.

```AADInternals
Set-AADIntAppRoleAssignment -ObjectId <SPNObjectId> -Rolene "Global Administrator"

```

# Privilege Tiers and Application Accounts:

- [ ]  Consider the privilege levels and tiers within the organization.
    - Test: Review the Azure AD roles and permissions assigned to different user accounts using AADInternals or Azure CLI.
    - Test: Conduct a privilege audit to ensure that users are assigned appropriate roles without excessive permissions.
```AADInternals

Set-AADIntAppRoleAssignment -ObjectId <SPNObjectId> -Rolene "Global Administrator"

```

- [ ]  Evaluate the usage of application accounts similar to Azure accounts.
    - Test: Create an application account using Azure CLI or Azure Portal and verify its functionality and access.
    - Test: Examine the application account's activity logs for unusual patterns that could indicate compromise.

```Azure CLI
az monitor activity-log list --resource-group <ResourceGroupne> --query "[?caller eq '<AppRegistrationId>']"


```

- [ ]  Determine if these accounts can be utilized for dropping into a cluster and performing lateral movement.
    - Test: Use PowerZure or PowerShell to authenticate with the application account and attempt to access and move within the cluster.
    

# Credentials and Lateral Movement:

- [ ]  Identify available credentials within the environment.
    - Test: Use PowerZure or PowerShell to list and identify available credentials, such as passwords, certificates, or tokens.
```AzADPSmodule

To list Azure AD applications and their credentials (you might need permissions to view these details):
Get-AzADApplication | ForEach-Object {
    $appId = $_.ApplicationId
    Get-AzADAppCredential -ObjectId $appId
}


To list service principals and their credentials:
Get-AzADServicePrincipal | ForEach-Object {
    $spId = $_.Id
    Get-AzADSpCredential -ObjectId $spId
}

```

    - Test: Assess the security of credential storage and retrieval mechanisms to ensure they are not vulnerable to common attack vectors.
```Powerzure
Get-PZKeyVaultSecret -Vaultne <YourKeyVaultne>

```

- [ ]  Assess the potential for lateral movement using these credentials.
    - Test:
    - Test: Evaluate the network segmentation and access control lists (ACLs) to verify they effectively limit lateral movement.
    
```Azure CLI
az network Steve rule list --Steve-ne <YourStevene> --resource-group <ResourceGroupne> --query "[].{ne:ne, Access:access, Direction:direction, Priority:priority}"
   
```