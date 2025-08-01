- **MSBuild**: A legitimate Microsoft tool used to build .NET applications. Attackers can use it to execute malicious payloads by embedding the payload in a project file (XML format), which MSBuild runs without triggering AV/EDR because it's a trusted tool.
    
- **Regsvr32**: A Windows utility that registers and unregisters DLLs. Attackers can abuse it to execute arbitrary scripts or payloads via a remote URL, bypassing application whitelisting and AV/EDR controls.
    
- **Rundll32**: A tool used to run functions within DLLs. Attackers can exploit it to run malicious code within a DLL or even run scripts like JavaScript or VBScript without alerting AV/EDR because it's a system-native tool.