
**SauronEye**  
Search tool to find specific files containing specific words, i.e., files containing passwords.  
@Credit to: https://github.com/vivami/SauronEye  
```bash
PowerSharpPack -SauronEye -Command "search /term:password"
```

**Snaffler**  
A tool for pentesters to help find delicious candy (sensitive files).  
@Credit to: https://github.com/SnaffCon/Snaffler  
```bash
PowerSharpPack -Snaffler -Command "find /term:password"
```

**Farmer**  
Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.  
@Credit to: https://github.com/mdsecactivebreach/Farmer  
```bash
PowerSharpPack -Farmer -Command "collect /target:TargetDomain"
```

