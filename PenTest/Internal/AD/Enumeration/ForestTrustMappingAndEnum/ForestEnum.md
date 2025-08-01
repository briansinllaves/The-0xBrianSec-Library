**Exploring Forests and Trust Relationships in AD (Pentest Context)**

Forests are the widest containers in Active Directory. Breaking forests and parent-child trust relationships can lead to unauthorized access to resources, privilege escalation, and issues across a wider range of targets. Check if SIDs appear in other domains and examine trust relationships.

1. **Get All Domain Controllers in the Current Domain:**

   ```powershell
   Get-DomainController -Domain
   ```

2. **Export Trust Mappings to a CSV File:**

   ```powershell
   Get-DomainTrustMapping -Server 10.2.4.1 -API | Export-CSV -NoTypeInformation DomainTrustMapping.csv
   ```

3. **Export Information About Foreign Group Members to a CSV File:**

   ```powershell
   Get-DomainForeignGroupMember | Export-CSV -NoTypeInformation DomainForeignGroupMember.csv
   ```

4. **Export Information About Foreign Users to a CSV File:**

   ```powershell
   Get-DomainForeignUser | Export-CSV DomainForeignUser.csv
   ```

5. **Export Domain Policy Data to a CSV File:**

   ```powershell
   Get-DomainPolicyData | Export-CSV DomainPolicyData.csv
   ```

6. **Get All Domains in the Current Forest:**

   ```powershell
   Get-Forest | Export-CSV Get-Forest.csv
   ```

7. **Get Details About the Current Forest:**

   ```powershell
   Get-ForestDomain -Verbose
   Get-ForestDomain -Forest nom.adh.ABCDal.com
   ```

8. **Get Users from the Current Forest:**

   ```powershell
   Get-DomainUser -Domain | Select-Object ne
   ```

9. **Get Users from a Specific Domain Within the Forest:**

   ```powershell
   Get-DomainUser -Domain a.m.a.ABCDnal.com | Select-Object ne
   ```

10. **Get All Global Catalogs for the Current Forest:**

    ```powershell
    Get-ForestGlobalCatalog
    Get-ForestGlobalCatalog -Forest eurocorp.local
    ```