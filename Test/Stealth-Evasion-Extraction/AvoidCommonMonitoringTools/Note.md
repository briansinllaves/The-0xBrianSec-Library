- Tools like **Sysmon** or **EDR solutions** monitor high-level activities such as:
    - Process creation (`CreateProcess`).
    - DLL loading (`LoadLibrary`).
    - Network connections or suspicious PowerShell commands.
    
- **Reflective injection** and **process hollowing** evade these monitoring systems because:
    - They don't involve creating new processes or loading DLLs in the conventional way.
    - The payload is injected directly into memory, reducing the chances of being flagged.
