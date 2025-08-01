**Bypassing AV Signatures for PowerShell - Invoke-Mimikatz**

- **Invoke-Mimikatz is THE most heavily signatured PowerShell script!**
- **We must rene it before scanning with AmsiTrigger to avoid access denied errors.**
- **Multiple detections require several changes:**

1. **Remove the comments:**
   - All comments in the script should be deleted to reduce detection chances.

2. **Modify each use of "DumpCreds":**
   - Change every instance of "DumpCreds" to "DC".

3. **Modify the variable nes of the Win32 API calls that are detected:**
   - Change variable nes for the following API calls:
     - "VirtualProtect"
     - "WriteProcessMemory"
     - "CreateRemoteThread"

4. **Reverse the strings that are detected and the Mimikatz Compressed DLL string:**
   - Reverse all detected strings, including the Mimikatz Compressed DLL string, to obfuscate them.

