**Finding Sensitive Information in Shared Content (Pentest Context)**

Shared content is a great place to find sensitive information and could potentially be poisoned with documents or icons that leak NTLM hashes to tools like Responder.

1. **Using Invoke-ShareFinder:**

   - Retrieve share information with specified options:

     ```powershell
     Invoke-ShareFinder -Verbose -Domain carnage.com -Server 10.42
     ```

   - Advanced options to search within a specific OU and domain controller:

     ```powershell
     Invoke-ShareFinder -DomainController 10.12.1.1 -Domain test-globalx.com -ComputerSearchBase "LDAP://OU=Application,OU=Tier 1,OU=PITY,OU=Global,DC=glob,DC=com" -ComputerLDAPFilter "(dnshostne=*)" -Threads 50 -Jitter .5 -ResultPageSize 5 -Verbose > sharefinder.txt
     ```

2. **Using SharpShares.exe:**

   - Find shared folders within a specified domain and output the results:

     ```plaintext
     .\SharpShares.exe shares /domain:test-globalx.com /threads:50 /ldap:servers /ou:"OU=Application,OU=Tier 1,OU=PT,OU=Global,DC=pglob,DC=com" /filter:SYSVOL,NETLOGON,IPC$,PRINT$ /verbose /outfile: /dc:ip
     ```

   - Retrieve share information and output to a file:

     ```plaintext
     .\SharpShares.exe /dc:10.1.1.27 /domain: ad.JOHNTHEHAMMER.com /outfile:SharpShares_MostRecentActivity.txt /threads:50 /verbose
     ```

