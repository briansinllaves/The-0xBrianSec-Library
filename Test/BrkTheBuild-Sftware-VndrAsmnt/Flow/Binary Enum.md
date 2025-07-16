### **File Explorer**

- **Check:**
  - **XML, XAML, logs:** Look for network-related information, credentials, hints to operations, or developer notes.
  - **Application logs:** Check for cleartext keys or information about failures that might be exploitable for impersonation.

- **Scripts:**
  - Ensure you have permissions over the script.
  - Manually review the code for potential vulnerabilities.
  - Run the scripts and monitor them using **ProcMon** to see what processes are initiated.
    - Look for any subscripts that run.
    - Examine triggers and actions in **ProcMon** to understand what the script is doing.

- **Config Files:**
  - Open configuration files in Notepad.
  - Always check for custom application files, such as **ABCD apps, .dat files, .ini files**.
  - Use the following command to locate executable files:
    ```powershell
    Get-ChildItem -Depth 5 -Include "*.exe"
    ```

---

### **Privilege and Access Control (PAC)**

- **Tools:**
  - Use **AccessEnum** or **icacls**:
    - `/t` for all subdirectories.
    - `/l` for operations on a symlink instead of its destination.
  
- **Key Points:**
  - **Who has access:** Determine who has access to items within a directory or registry key.
  - **System vs. AppData Control:** We don’t have control over system files, but we do have control over **AppData**, such as `%localappdata%?ms?onedrivestandalone.exe`.

---

### **Process Explorer (ProcExp)**

- **Look at:**
  - **ned Pipes:** Investigate ned pipes to understand inter-process communication.
  - **3rd Party Software:** Identify what third-party software is in use.
    - Check for known vulnerabilities.
    - Examine what operations (write, create, read) the software performs.
  
- **Run as User vs. Admin:**
  - Compare behaviors when running **Process Explorer** as a user and as an admin to identify any differences.
  - Focus on user-writable, executable, and deletable directories, files, system files, and registry keys.

- **Handles:**
  - **Check All-Access Permissions:** Use **Process Explorer** to view handles associated with a process. Check if any of these handles have "all-access" permissions by looking at the security descriptors. 
    - **Steps:**
      1. Open **Process Explorer** and locate the process you’re interested in.
      2. Right-click on the process and select `Properties`.
      3. Go to the `Handles` tab to view the handles.
      4. Look for handles with high permissions (e.g., `0x001F0FFF`).
  - **Duplicate or Steal Handles:** 
    - **Using Process Explorer:**
      1. Identify a handle with all-access permissions.
      2. Right-click the handle and choose `Duplicate Handle` to create a new handle with the same access rights.
      3. Use tools like **Mimikatz** or custom scripts to attempt to steal or manipulate these handles, especially those from privileged processes.

- **Privileged Execution:**
  - Identify what is run with elevated privileges and the handles that process has.
  - Look at user-controlled folder associations and potential exploits.

- **See Properties:**
  - **Services:** Review the properties of services.
  - **TCP/IP Addresses:** Note any associated TCP/IP addresses.
  - **Security Tab:** Review permissions and privileges.
  - **Environment Tab:** Examine environment variables.
  - **Parse Strings:** Extract and analyze strings for further clues.

---

### **Process Monitor (ProcMon)**

- **Monitor:**
  - Use **ProcMon** to monitor all clicks and interactions.
  - Focus on processes running with the highest privileges, both at boot and runtime.

- **Logging:**
  - Enable startup process logging in **ProcMon** (Note: This can cause crashes but is useful for detailed analysis).

- **Task Scheduler:**
  - Run an executable via **Task Scheduler** (`taskschd.msc`) and monitor its behavior in **ProcMon**.

- **Filter:**
  - Exclude `C:\Windows\System32` and `HKLM` to focus on user-accessible paths.

- **Look at:**
  - **File/Folder Operations:** Does the process open files/folders?
  - **DLL Analysis:** 
    - Does the product inject DLLs?
    - Can you manipulate the DLL in user-accessible space?
    - What are the DLLs trying to do and where are they pointing?
  - **Out of Place Elements:** Is there anything unusual or out of place?
  - **User Write Permissions:** Are they exploitable?
  - **Buffer Overflow:** Review results for potential buffer overflows.
  - **PATH NOT FOUND:** Investigate missing paths.
  
- **Proc Modules and Stack:**
  - Examine the modules and stack to see what is being called.
  - Look for exploit requirements such as **Symlinks**, **COM**, **DLL**, **Pipes**, and **RPC**.

---

### **PE Studio**

- **Focus:**
  - **Indicators of Compromise:** Look for suspicious indicators like unusual strings, unexpected connections, or strange behaviors in the binary.
  - **Directory Structures:** Analyze the directory structure within the binary to identify any non-standard or potentially malicious paths.
  - **IAT/EAT Analysis:** 
    - **IAT (Import Address Table):** 
      - Review the external functions that the program is importing. Suspicious or unexpected imports could indicate malicious behavior, especially if the binary is calling functions that are not commonly associated with its typical functionality (e.g., network functions in a program that shouldn't need network access).
      - **Suspicious Imports:** Look for imports like `VirtualAlloc`, `WriteProcessMemory`, `LoadLibrary`, and `GetProcAddress`, as these are often used in malicious activities such as process injection, dynic linking of malicious code, or evasion techniques.
    - **EAT (Export Address Table):** 
      - Analyze the functions that the binary is exporting. Functions that are exported but seem unrelated to the primary purpose of the application can be used in unexpected ways, such as exposing unintended functionality or being leveraged for exploitation.
  - **Tools for Deeper Inspection:** 
        - **API Monitor:** Use **API Monitor** to observe and log calls to the imported APIs in real-time, which can help you identify suspicious or unexpected behavior. This tool can be particularly useful to see how the program interacts with the system and other processes.

---

### **RPC Investigation**

- **Advanced Analysis:**
  - **Identify Interfaces:** Use tools like **RpcView** to discover RPC interfaces and bind to them.
  - **Data Manipulation:** Determine if the interface accepts data that you can manipulate, such as malformed inputs that could lead to exploitation.

- **Reverse Engineering:**
  - **Use IDA Pro and x64 Debugger:** 
    - Trace the data path within the application.
    - Identify vulnerable functions, like `strcpy`, which could lead to buffer overflows.
  - **Advanced Techniques:** 
    - **Exclude Fuzzing and ICACLS:** Focus on more direct analysis techniques unless fuzzing is explicitly required for the task.
    - **Driver and Kernel Analysis:** 
      - Use **IDA Pro** or **Ghidra** to analyze driver code.
      - Trace the code path from the driver to the DLL and back to the kernel, focusing on potential vulnerabilities.
  - **Bug Class Learning:** 
    - Familiarize yourself with different bug classes (like buffer overflows, use-after-free, etc.) to understand how they might be exploited in the context of your analysis.
