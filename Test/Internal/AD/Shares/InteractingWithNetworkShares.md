### **Running PowerShell as a Specific User**

- **Command:**
  ```plaintext
  runas /user:ABCDglb\bhous /netonly powershell.exe
  ```
  - **Use Case:** Execute PowerShell commands under a different user context, useful for accessing network resources with specific credentials.

---

### **Viewing and Mounting Network Drives**

1. **View Available Network Drives:**
   - **Command:**
     ```plaintext
     net view \\domain\drive
     ```
   - **Use Case:** Lists available shares on a specified domain or server.

2. **Mount a Network Drive:**
   - **Command:**
     ```plaintext
     net use * \\domain\drive
     ```
   - **Use Case:** Mounts the specified network share to an available drive letter.

3. **Change Directory to Mounted Drive:**
   - **Command:**
     ```plaintext
     cd x:\
     ```
   - **Use Case:** Navigates to the mounted drive to interact with its contents.

4. **Dismount the Drive:**
   - **Command:**
     ```plaintext
     net use /delete x:
     ```
   - **Use Case:** Unmounts the previously mounted network drive.

---

### **Creating Directories and Accessing Shares**

1. **Create a Directory on the Share:**
   - **Command:**
     ```plaintext
     mkdir x:\images
     ```
   - **Use Case:** Creates a new directory on the mounted network share.

2. **Access a Share via IP Address:**
   - **Command:**
     ```plaintext
     net use * \\ip\share
     ```
   - **Use Case:** Mounts a network share using the server's IP address instead of its domain ne.

---

### **SMB Client Operations**

1. **Basic Operations with smbclient:**
   - **Command:**
     ```plaintext
     smbclient -U domain\bhouston \\\\ip\\share
     ```
   - **Use Case:** Interacts with SMB shares, allowing you to list files, upload, or download files directly.

2. **Advanced Operations with smbclient.py:**
   - **Command:**
     ```plaintext
     python3 smbclient.py -hashes aad3b4351404ee:<Redacted>administrator@10.24.7.9
     ```
   - **Use Case:** Perform more advanced SMB operations, such as file enumeration or downloading all files in a directory, using NTLM hashes for authentication.
