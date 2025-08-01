**Getting Domain Controller Information (Pentest Context)**

**Options with Better OPSEC:**

1. **NLTest:**

   - List all domain controllers:
     ```plaintext
     nltest /dclist:<domain>
     ```

2. **NSLookup:**

   - Discover domain controllers via DNS SRV records:
     ```plaintext
     nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>
     ```
     - See "NS Discovery" for more details.

3. **PowerView:**

   - Get domain controller information:
     ```powershell
     Get-DomainController
     ```

4. **NetworkManager CLI (nmcli):**

   - Show domain ne and DNS information:
     ```plaintext
     nmcli dev show eth0
     ```
