
**Lockless**  
Allows for the copying of locked files.  
@Credit to: https://github.com/GhostPack/Lockless  
```bash
PowerSharpPack -Lockless -Command "copy /source:C:\LockedFile.txt /destination:D:\"
```

**SharpClipboard**  
C# Clipboard Monitor.  
@Credit to: https://github.com/slyd0g/SharpClipboard  
```bash
PowerSharpPack -SharpClipboard -Command "monitor"
```

**SharpPrinter**  
Discover Printers + check for vulnerabilities.  
@Credit to: https://github.com/rvrsh3ll/SharpPrinter  
```bash
PowerSharpPack -SharpPrinter -Command "discover"
PowerSharpPack -SharpPrinter -Command "check"
```

**StickyNotesExtract**  
Extracts data from the Windows Sticky Notes database.  
@Credit to: https://github.com/V1V1/SharpScribbles  
```bash
PowerSharpPack -StickyNotesExtract -Command "extract"
```

**UrbanBishop**  
Creates a local RW section in UrbanBishop and then maps that section as RX into a remote process. Shellcode loading made easy.  
@Credit to: https://github.com/FuzzySecurity/Sharp-Suite  
```bash
PowerSharpPack -UrbanBishop -Command "inject /target:TargetProcess /payload:Shellcode"
```

**SharpOxidResolver**  
IOXIDResolver from AirBus Security/PingCastle.  
@Credit to: https://github.com/vletoux/pingcastle/  
```bash
PowerSharpPack -SharpOxidResolver -Command "resolve /target:TargetMachine"
```
