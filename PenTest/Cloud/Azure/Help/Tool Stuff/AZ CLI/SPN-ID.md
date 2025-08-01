
Note:

- The Azure "client id" is a unique identifier for Azure resources.
- The "service principal id" is the unique identifier for Azure AD.

- Get user GUID
```
Get-DomainUser <target>  

```

- Check roles assigned to a Service Principal ne (SPN):

    ```
    az role assignment list --assignee <spn-id> --include-groups --include-inherited  
    ```


    Example command:
    ```
    az role assignment list --assignee c50c4fcc-2676-42d4-a789-39569771dcb0 --include-groups --include-inherited  
    ```


- Get Service Principal ID:
    ```
    az ad sp list --filter "servicePrincipalnes/any(c:c eq '$spnid')"  
    ```

spn recon

```
get-adtargets from powerzure on the new spns

```