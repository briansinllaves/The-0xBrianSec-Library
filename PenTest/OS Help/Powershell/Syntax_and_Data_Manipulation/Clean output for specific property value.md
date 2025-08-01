### **Piping Cmdlet Output to a Variable and Looping Through Recursively**

- **Step 1: Call a Cmdlet, Filter Output, and Save Property Value**
  - Retrieve domain trusts and store them in a variable:
    ```powershell
    $sids = Get-DomainTrust -Domain ABCDglb.com -Server 10.1.1.3
    ```

- **Step 2: Hide Table Headers in Output**
  - Format the output to show only the `Targetne` property without headers, and save it to a file:
    ```powershell
    $sids | ft Targetne -HideTableHeaders | Out-File dt7.txt
    ```

- **Step 3: Remove PowerShell Top Line Information**
  - Remove the first line (headers) from the file and save the clean output:
    ```powershell
    Get-Content .\dt7.txt | Select-Object -Skip 1 | Out-File .\dt2sid.txt
    ```

- **Step 4: Loop Through the Cleaned Data**
  - Read the cleaned file and iterate through each line using `ForEach-Object`:
    ```powershell
    PS C:\> ls dt2sid.txt | ForEach-Object {cat $_}
    ```

  - Alternatively, loop through the array of domain SIDs:
    ```powershell
    foreach ($domain in $sids) {
        Get-DomainSID -Domain $domain -Server 10.6.6.3
    }
    ```

- **Step 5: Use the Clean Text File for Further Iteration**
  - Read the cleaned text file and loop through the values in a new cmdlet:
    ```powershell
    $sids = Get-Content dt2sid.txt
    foreach ($domain in $sids) {
        Get-DomainSID -Domain $domain -Server 10.1.1.2
    }
    ```

- **Example with a New Set of Domain SIDs:**
  - Fetch domain trusts again and iterate through them:
    ```powershell
    $sids = Get-DomainTrust -Domain ABCDglb.com -Server 10.6.6.3
    foreach ($domain in $sids) {
        Get-DomainSID -Domain $domain -Server 10.1.1.3
    }
    ```

