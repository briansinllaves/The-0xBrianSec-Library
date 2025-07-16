**Enumeration Guide for Domain (Pentest Context)**

1. **Enumerate the Following for the Domain:**

   - **Users:**
     ```powershell
     Get-ADUser -Filter * | Select-Object ne
     ```

   - **Computers:**
     ```powershell
     Get-ADComputer -Filter * | Select-Object ne
     ```

   - **Domain Administrators:**
     ```powershell
     Get-ADGroupMember -Identity "Domain Admins" | Select-Object ne
     ```

   - **Enterprise Administrators:**
     ```powershell
     Get-ADGroupMember -Identity "Enterprise Admins" | Select-Object ne
     ```

   - **List All OUs:**
     ```powershell
     Get-ADOrganizationalUnit -Filter * | Select-Object ne
     ```

   - **List All Computers in the StudentMachines OU:**
     ```powershell
     Get-ADComputer -SearchBase "OU=StudentMachines,DC=domain,DC=com" -Filter * | Select-Object ne
     ```

   - **List the GPOs:**
     ```powershell
     Get-GPO -All | Select-Object Displayne
     ```

2. **Enumerate GPO Applied on the priv OU:**
   ```powershell
   Get-GPResultantSetOfPolicy -Scope Computer -Target "OU=priv,DC=domain,DC=com" | Select-Object Displayne
   ```

3. **ACL for the Domain Admins Group:**
   ```powershell
   Get-ACL "AD:\CN=Domain Admins,CN=Users,DC=domain,DC=com" | Select-Object -ExpandProperty Access
   ```

4. **All Modify Rights/Permissions for the Student:**
   ```powershell
   Get-ACL "AD:\CN=Student,CN=Users,DC=domain,DC=com" | Select-Object -ExpandProperty Access
   ```

5. **Enumerate All Domains in the moneycorp.local Forest:**
   ```powershell
   Get-ADForest -Identity moneycorp.local | Select-Object Domains
   ```

6. **Map the Trusts of the dollarcorp.moneycorp.local Domain:**
   ```powershell
   Get-ADTrust -Filter {TargetDomain -eq "dollarcorp.moneycorp.local"} | Select-Object ne, TrustType, TrustDirection
   ```

7. **Map External Trusts in the moneycorp.local Forest:**
   ```powershell
   Get-ADTrust -Filter {TrustType -eq "External"} | Select-Object ne, TrustType, TrustDirection
   ```

8. **Identify External Trusts of the dollarcorp Domain:**
   ```powershell
   Get-ADTrust -Filter {Source -eq "dollarcorp"} | Select-Object ne, TrustType, TrustDirection
   ```

   - **Enumerate Trusts for a Trusting Forest:**
     ```powershell
     Get-ADTrust -Filter {TargetDomain -like "*dollarcorp*"} | Select-Object ne, TrustType, TrustDirection
     ```