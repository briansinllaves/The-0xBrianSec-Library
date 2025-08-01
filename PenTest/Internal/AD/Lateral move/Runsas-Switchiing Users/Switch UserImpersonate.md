**Pentest Note: User Impersonation with PowerShell**

---

This process allows you to temporarily impersonate another user using their credentials, which can be useful for testing or accessing resources that require specific permissions.
After performing the necessary actions, you can easily revert to your original user context. 
### Step 1: Obtain User Credentials

- **Prompt for Credentials:**
  ```powershell
  $cred = Get-Credential
  ```

This command will prompt you to enter the credentials (userne and password) of the user you want to impersonate.

### Step 2: Invoke User Impersonation

- **Invoke User Impersonation:**
  ```powershell
  Invoke-UserImpersonation -Verbose -Credential $cred
  ```

This command uses the provided credentials to impersonate the specified user. The `-Verbose` flag provides detailed output of the impersonation process.

### Step 3: Revert to Original User

- **Revert to Original User:**
  ```powershell
  Invoke-RevertToSelf
  ```

This command stops the impersonation and reverts to the original user context.

