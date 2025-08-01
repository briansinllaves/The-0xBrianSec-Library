### Steps to Identify Injectable Processes:

1. **Check Process Privileges**:
   - Use tools like `Task Manager`, `Process Explorer`, or `wmic` to see which processes are running under `SYSTEM` or higher privileges.
     - `wmic process get ne,processid,sessionid`
     - In **Process Explorer**, look for processes running under `NT AUTHORITY\SYSTEM` or a domain administrator account.

2. **Monitor EDR-Related Processes**:
   - Look for EDR agents (e.g., `CylanceSvc.exe`, `CarbonBlack.exe`, `CrowdStrike.exe`). Injecting into these may result in detection.
   - Avoid highly protected or sensitive processes like `winlogon.exe`, `csrss.exe`, `lsass.exe`.

3. **Target Non-Protected, Long-Running Processes**:
   - **explorer.exe**: The Windows Explorer process is a common target. It's long-running, user-level, and not tightly monitored by EDRs in most cases.
   - **svchost.exe**: This service host process runs multiple Windows services. However, it’s often monitored, so consider avoiding it unless you know it’s not watched.
   - **User Applications**: Look for user-level processes like browsers (`chrome.exe`, `firefox.exe`), which are long-running and typically trusted by the system.

4. **Analyze Process Integrity Levels**:
   - Processes have integrity levels (Low, Medium, High, System). Use `Process Explorer` or `Get-Process` in PowerShell to identify processes running at a high integrity level.
   - `explorer.exe` typically runs at **Medium Integrity**, so it may not immediately escalate privileges but can be a good target for persistence or lateral movement.

5. **Use Built-in Windows Tools to List Running Processes**:
   
   - **Tasklist**: 
     ```
     tasklist /v
     ```
   
   - **wmic**:
     ```
     wmic process list full
     ```
 
   These will give you a quick overview of running processes and their owners.

6. **Check for Open Handles and Modules**:
   - Use `Process Explorer` or similar tools to see which processes have open handles to critical resources like files, memory, or threads. Processes interacting with sensitive data may be better injection targets.

### Tool-Assisted Process Selection:
- **Process Hacker**: Displays process tree, privileges, handles, and DLLs loaded by each process. It can help identify potential targets for injection.

- **PowerSploit** or **Invoke-PSInject**: Tools like these allow you to enumerate running processes and identify suitable candidates for injection by examining memory permissions and process details.
  
### Practical Injection Considerations:
1. **Don't target too small processes**: Processes with limited functionality may crash if you inject complex shellcode.
2. **Don't inject into very large processes unnecessarily**: EDR tends to monitor high-value processes, so try to find something balanced—trusted and necessary, but not critical.
3. **Look for processes performing network activity**: Processes involved in network communications might be good candidates since they often allow lateral movement or data exfiltration (e.g., `chrome.exe`, `firefox.exe`).
