**winPEAS**  
Performs privilege escalation checks on Windows systems, automating the detection of vulnerabilities.  
@Credit to: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS  
```bash
PowerSharpPack -winPEAS -Command "all"
PowerSharpPack -winPEAS -Command "fast"
PowerSharpPack -winPEAS -Command "audit"
```

**Watson**  
Enumerates missing security patches and suggests exploits for privilege escalation.  
@Credit to: https://github.com/rasta-mouse/Watson  
```bash
PowerSharpPack -Watson -Command "all"
PowerSharpPack -Watson -Command "KB list"
PowerSharpPack -Watson -Command "exploit check"
```

**SharpUp**  
A C# port of various PowerUp functionalities for privilege escalation enumeration.  
@Credit to: https://github.com/GhostPack/SharpUp  
```bash
PowerSharpPack -SharpUp -Command "all"
PowerSharpPack -SharpUp -Command "services"
PowerSharpPack -SharpUp -Command "credentials"
```

**Tokenvator**  
A tool to elevate privilege with Windows Tokens.  
@Credit to: https://github.com/0xbadjuju/Tokenvator  
```bash
PowerSharpPack -Tokenvator -Command "list"
PowerSharpPack -Tokenvator -Command "impersonate /userne:admin"
PowerSharpPack -Tokenvator -Command "elevate /sid:S-1-5-18"
```

**BadPotato**  
itm4ns Printspoofer in C#.  
@Credit to: https://github.com/BeichenDream/BadPotato  
```bash
PowerSharpPack -BadPotato -Command "exploit"
```

