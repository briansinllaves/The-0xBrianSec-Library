### **Pentest Note: Extracting and Using DPAPI Keys**

---

#### **Overview of DPAPI:**
The Data Protection API (DPAPI) is a Windows feature that provides confidentiality for stored credentials by encrypting them under the security context of a user or system account.

---

### **Tools for Extracting DPAPI Keys:**

#### **1. DonPAPI:**
- **Purpose:** Retrieves credentials and other sensitive data protected by DPAPI.
- **Usage:**
  ```plaintext
  DonPAPI.py <domain>/<user>:<password>@<target>
  ```
- **Explanation:** Use DonPAPI by providing domain credentials to target a machine and extract DPAPI-protected data, which can include credentials for various services and applications.

#### **2. Mimikatz:**
- **Purpose:** Extracts DPAPI keys and decrypts protected data.
- **Usage:**
  ```plaintext
  mimikatz.exe "sekurlsa::dpapi"
  ```
- **Explanation:** This command in Mimikatz dumps DPAPI keys from the current LSASS process, which can then be used to decrypt DPAPI-protected data.

#### **3. Secretsdump:**
- **Purpose:** Primarily for hash extraction, but can also be used to decrypt DPAPI-protected credentials with the appropriate keys.
- **Usage:**
  ```plaintext
  secretsdump.py <domain>/<user>:<password>@<ip>
  ```
- **Explanation:** Use Secretsdump to extract and leverage DPAPI keys obtained via other tools (like Mimikatz) to decrypt credentials stored in the domain controller's database.

---

### **Using Extracted DPAPI Keys:**

Once you've extracted the DPAPI keys, you can decrypt DPAPI-protected data, which might include:
- Wi-Fi passwords
- Credentials stored by browsers
- Sensitive data encrypted by various applications

#### **Steps:**
1. **Extract the DPAPI keys:**
   - Obtain the keys with tools like Mimikatz by gaining administrative access to the system.
  
2. **Decrypt the data:**
   - Use the extracted keys in conjunction with tools or scripts to decrypt the DPAPI-protected data of interest.

---
