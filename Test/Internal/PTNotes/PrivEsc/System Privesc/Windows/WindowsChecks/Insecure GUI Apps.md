### Insecure GUI Apps

1. **RDP to Windows VM:**
   ```plaintext
   rdesktop -u user -p password321 MACHINE_IP
   ```

2. **Exploit Admin-Painted Application:**
   - Start `AdminPaint`.
   - In the Open dialog, navigate to `file://c:/windows/system32/cmd.exe`.
   - Spawns a command prompt running with admin privileges.

---
