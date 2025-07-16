**SharpView**  
C# implementation of PowerView for Active Directory enumeration.  
@Credit to: https://github.com/tevora-threat/SharpView  
```bash
PowerSharpPack -SharpView -Command "all"
PowerSharpPack -SharpView -Command "domain"
PowerSharpPack -SharpView -Command "user"
```

**SharpHound3**  
C# Data Collector for the BloodHound Project, focusing on Active Directory enumeration and analysis.  
@Credit to: https://github.com/BloodHoundAD/SharpHound3  
```bash
PowerSharpPack -SharpHound3 -Command "all"
PowerSharpPack -SharpHound3 -Command "session collection"
PowerSharpPack -SharpHound3 -Command "group collection"
```

**SharpSniper**  
Finds specific users in Active Directory via their userne and logon IP address.  
@Credit to: https://github.com/HunnicCyber/SharpSniper  
```bash
PowerSharpPack -SharpSniper -Command "finduser /ne:userne"
PowerSharpPack -SharpSniper -Command "findlogon /ip:192.168.1.1"
```

**LdapSignCheck**  
C# project to check LDAP signing.  
@Credit to: https://github.com/cube0x0/LdapSignCheck  
```bash
PowerSharpPack -LdapSignCheck -Command "check"
```

**SharpLdapRelayScan**  
C# Port of LdapRelayScan.  
@Credit to: https://github.com/klezVirus/SharpLdapRelayScan  
```bash
PowerSharpPack -SharpLdapRelayScan -Command "scan /target:TargetDomain"
```
