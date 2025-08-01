**Obfuscating PowerShell Scripts**

We can use the AMSITrigger tool to identify the exact part of a script that is detected.

- **AMSITrigger Tool**: [AMSITrigger GitHub](https://github.com/RythmStick/AMSITrigger)
  - **Usage**: Simply provide the path to the script file to scan it:
  
    ```plaintext
    AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke-PowerShellTcp_Detected.ps1
    ```

- **Full Obfuscation of PowerShell Scripts**:
  - **Invoke-Obfuscation Tool**: [Invoke-Obfuscation GitHub](https://github.com/danielbohannon/Invoke-Obfuscation)
  - This tool is used for obfuscating the AMSI bypass in the CRTP