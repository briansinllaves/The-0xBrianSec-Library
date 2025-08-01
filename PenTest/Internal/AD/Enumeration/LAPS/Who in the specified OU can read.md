**Identifying Who Can Read LAPS in a Specified OU (Pentest Context)**

1. **Check Who Can Read LAPS in a Specified OU:**

   ```powershell
   Get-DomainOU -Distinguishedne <T0_computer_OU> -FullData | Get-ObjectAcl -ResolveGUIDs | Where-Object { ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty') }
   ```

2. **Check Who Can Read LAPS in a Domain with a Specified Server:**

   ```powershell
   Get-DomainOU -Identity ABCDglb.com -Server 10.240.86.140 | Get-ObjectAcl -ResolveGUIDs | Where-Object { ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty') }
   ```

3. **Store OU Objects and ACLs in Variables for Further Processing:**

   ```powershell
   $OUObjs = Get-DomainOU -Distinguishedne <T0_computer_OU> -FullData
   $Acls = ($OUObjs | Get-ObjectAcl -ResolveGUIDs)
   $output = ($Acls | Where-Object { ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty') })
   ```

The above commands will help you identify which users or groups have read permissions on the LAPS passwords in a specified OU.