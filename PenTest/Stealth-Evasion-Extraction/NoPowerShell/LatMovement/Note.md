- **SMB/NTLM Relays:** Use `Impacket` tools like `wmiexec.py`, `smbexec.py`, or `secretsdump.py` to execute commands over SMB or relay credentials.

- **WMI:** Execute commands or gather info using WMI without PowerShell using `wmic.exe` from the command line.

- **Pass-the-Hash:** Tools like `mimikatz` or `Impacket` can be used to pass NTLM hashes to move laterally.

- **RDP or SMB:** Leverage valid credentials to log in via RDP or SMB if available.