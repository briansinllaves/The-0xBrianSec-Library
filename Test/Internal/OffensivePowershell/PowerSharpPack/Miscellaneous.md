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

