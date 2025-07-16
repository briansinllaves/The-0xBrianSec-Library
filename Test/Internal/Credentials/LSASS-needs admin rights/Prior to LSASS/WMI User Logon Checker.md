### **Pentest Note: WMI User Logon Checker**

---

**Purpose:**
This C# tool is designed to check via WMI which users are logged onto a specified computer and to determine their logon types. The tool helps identify if a computer is worth the effort for an LSASS (Local Security Authority Subsystem Service) dump based on the types of logins present.

---

**Functionality:**

- **Reads a List of Target Computers:**
  - The tool takes in a list of target computers to scan.

- **Checks for Non-Local Account Logins:**
  - It identifies logins that are not local accounts, focusing on accounts that could be valuable for further exploitation.

- **Logs Results:**
  - Outputs the results both to a file and the console, providing details on each user session.

- **Filters by Logon Types:**
  - Only logon types that are typically valuable for credential dumping are listed:
    - **Interactive**
    - **Batch**
    - **Service**
    - **NetworkCleartext**
    - **NewCredentials**
    - **RemoteInteractive**
    - **CachedInteractive**

---

**Example Output:**

```plaintext
Users on: IN-BOM01
    Userne: bri\pwpb
    LogonType: RemoteInteractive
    AuthPackage: Kerberos
    LogonTime: 05:45:33 28-09-2023

Users on: IN-BUV1
    Userne: PWLB\IN-SCOR
    LogonType: Service
    AuthPackage: Kerberos
    LogonTime: 11:23:39 18-10-2023
```

---

**Usage:**

1. **List of Targets:** 
   - The tool reads in a list of target machines to scan via WMI.

2. **Scan Process:**
   - For each target, the tool checks for active user sessions that match the valuable logon types.

3. **Output:**
   - Results are logged to a file and displayed in the console, showing which users are logged on, their logon types, the authentication package used (e.g., Kerberos), and their logon times.

---