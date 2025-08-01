### **Pentest Note: Mimikatz Usage for Credential Dumping**

---

**Mimikatz** is a powerful post-exploitation tool that allows attackers to interact with Windows security components to extract credentials, including from the SAM database and Active Directory.

---

#### **Key Mimikatz Commands:**

#### **1. LSADUMP::DCSync**
- **Purpose:** Request a Domain Controller (DC) to synchronize an object, effectively allowing you to pull password data for accounts.
- **Usage:**
  ```plaintext
  mimikatz.exe "lsadump::dcsync /domain:<domain> /user:<userne>"
  ```
- **Explanation:** This command simulates the behavior of a Domain Controller replicating account credentials, providing password hashes without needing to execute code directly on the DC.

---

#### **2. LSADUMP::LSA**
- **Purpose:** Retrieve SAM/AD enterprise credentials directly from the Local Security Authority (LSA) server.
- **Usage:**
  ```plaintext
  mimikatz.exe "lsadump::lsa /patch"
  ```
- **Explanation:** This allows Mimikatz to access and dump credentials from the SAM database or Active Directory, either by patching in-memory or injecting necessary code.

- **Specific Account Credential Extraction:**
  - **Command:** 
    ```plaintext
    mimikatz.exe "lsadump::lsa /patch /ne:krbtgt"
    ```
  - **Use Case:** Extracts the credentials specifically for the `krbtgt` account, often used in Golden Ticket attacks.

---

#### **3. LSADUMP::SAM**
- **Purpose:** Dump local account credentials from the SAM database.
- **Usage:**
  ```plaintext
  mimikatz.exe "lsadump::sam"
  ```
- **Explanation:** This command retrieves the SysKey and uses it to decrypt SAM entries, extracting credentials for all local accounts on a Windows machine. Useful for compromising local administrator accounts or other users.

---

**Summary:** Mimikatz, through the LSADUMP commands, provides extensive capabilities to extract credentials from both local machines and domain controllers. These commands are essential for lateral movement and privilege escalation within a compromised network.