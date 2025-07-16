**Checking Service Account Permissions in AD**

 filter and check the necessary permissions for a service account in Active Directory by using its SID.

1. **Import PowerView Module:**

   ```powershell
   Import-Module .\PowerView.ps1
   ```

2. **Use the SID of the service account:**

   - Identify the SID of the service account you want to check permissions for.

3. **Get Domain Object ACL (Access Control List):**

   ```powershell
   $domainAcl = Get-ObjectAcl -Distinguishedne "DC=domain,DC=com"
   ```

4. **Filter for Service Account Permissions:**

   - Replace `'S-1-5-21-...'` with the actual SID of the service account.

   ```powershell
   $serviceAccountPermissions = $domainAcl | Where-Object { $_.SecurityIdentifier -eq 'S-1-5-21-...' }
   ```

5. **Check for Necessary Permissions:**

   ```powershell
   $relevantPermissions = $serviceAccountPermissions | Where-Object { $_.ActiveDirectoryRights -match 'CreateChild|DeleteChild|WriteProperty' }
   ```

6. **Output:**

   ```powershell
   $relevantPermissions | Format-Table -AutoSize
   ```
