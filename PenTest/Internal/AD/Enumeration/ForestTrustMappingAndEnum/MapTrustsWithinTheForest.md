**Map Trusts Within the Forest (Pentest Context)**

1. **Get a List of All Domain Trusts for the Current Domain Using PowerView:**

   ```powershell
   Get-DomainTrust
   ```

2. **Get a List of Domain Trusts for a Specific Domain with a Specified Server:**

   ```powershell
   Get-DomainTrust -Domain ca.n.ad.prnal.com -Server 10.2.4.2
   ```

3. **Get Details on External Trusts for a Specific Forest:**

   ```powershell
   Get-ForestDomain -Forest eurocorp.local | ForEach-Object { Get-DomainTrust -Domain $_.ne }
   ```

4. **List External Trusts in the Specific Forest:**

   ```powershell
   Get-ForestDomain | ForEach-Object { Get-DomainTrust -Domain $_.ne } | Where-Object { $_.TrustAttributes -eq "FILTER_SIDS" }
   ```