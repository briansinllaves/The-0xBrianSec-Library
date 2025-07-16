**Domain Controller Information and Account Analysis Using AD Explorer**

1. **List All Domain Controllers:**

   - Use `nltest` to get a list of all domain controllers in the specified domain:
     ```plaintext
     nltest /dclist:ABCDglb.com
     ```

2. **Add PDC to AD Explorer and Take a Snapshot:**

   - Add the Primary Domain Controller (PDC) to AD Explorer for easy access and take a snapshot for documentation and analysis.

3. **Considerations for Account Analysis:**

   - **AdminCount:**
     - AdminCount is not always relevant. It is possible to be an admin on some hosts even if AdminCount is set to zero.
   
   - **Password Last Changed:**
     - Include a filter to check when the password was last changed. Older passwords are generally better targets, but new accounts with weak passwords might also exist.

4. **PowerShell Command to Check Password Last Changed:**

   - Retrieve accounts and filter based on the password last changed date:
     ```powershell
     Get-ADUser -Filter * -Properties PasswordLastSet | Where-Object { $_.PasswordLastSet -lt (Get-Date).AddDays(-90) } | Select-Object ne, PasswordLastSet
     ```

By incorporating these steps and considerations, you can effectively gather domain controller information and analyze account details for potential vulnerabilities using AD Explorer.