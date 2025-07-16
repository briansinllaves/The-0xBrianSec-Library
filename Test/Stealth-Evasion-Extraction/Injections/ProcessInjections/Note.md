The **process injection code** techniques mentioned in our discussion can fall into different categories such as **thread hijacking**, **process hollowing**, or **APC injection**, depending on how the memory is allocated, how the injected code is executed, and how the execution flow is manipulated. Let me explain where each of the techniques fits:

### **Thread Hijacking**
   - **Thread hijacking** involves taking control of an **existing thread** in a running process, manipulating its execution context (registers, instruction pointer), and forcing it to execute your code (e.g., shellcode or a PE).
   - **Key Characteristics**:
     - You suspend a running process's thread using `SuspendThread`.
     - Modify the thread’s context (using `GetThreadContext`/`SetThreadContext`).
     - Point the **instruction pointer (EIP/RIP)** of that thread to your injected code.
     - Resume the thread with `ResumeThread` so that it executes your payload.
   - **Relation to the Code Above**: If you are injecting code into a process and hijacking an existing thread to execute it (e.g., by modifying the thread’s context), this would be considered **thread hijacking**.
     - Example: You inject shellcode into a suspended thread, modify its instruction pointer to point to the injected shellcode, and then resume the thread.

### Example of **Thread Hijacking** in C++:
```cpp
// Example of thread hijacking to execute shellcode in an existing thread

HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);
SuspendThread(hThread);

// Get the current thread context
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(hThread, &ctx);

// Modify the instruction pointer (EIP/RIP) to point to the injected shellcode
ctx.Rip = (DWORD64)shellcodeAddress;
SetThreadContext(hThread, &ctx);

// Resume the thread, which now executes the shellcode
ResumeThread(hThread);
```

### **Process Hollowing**
   - **Process hollowing** involves creating a legitimate process in a **suspended state** (e.g., `svchost.exe`), then "hollowing out" its memory by **unmapping the legitimate code** and **replacing it with malicious code** (such as a PE or shellcode).
   - After the legitimate code is removed, the attacker injects their payload into the process’s memory space and **resumes the process**, which now executes the injected code.
   - **Key Characteristics**:
     - Create a suspended process using `CreateProcess`.
     - Use `NtUnmapViewOfSection` to hollow out the legitimate process’s memory.
     - Allocate memory using `VirtualAllocEx` and inject the payload.
     - Resume the process with `ResumeThread`.
   - **Relation to the Code Above**: The code that creates a **suspended process** (e.g., `svchost.exe`), removes its legitimate memory, and replaces it with your own payload, would fall under **process hollowing**.

### Example of **Process Hollowing** in C++:
```cpp
// Example of process hollowing to replace a legitimate process with malicious code

STARTUPINFO si = { sizeof(si) };
PROCESS_INFORMATION pi;
CreateProcess(L"C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// Unmap the legitimate executable's memory
NtUnmapViewOfSection(pi.hProcess, (PVOID)0x400000);

// Inject your malicious PE or shellcode into the hollowed process
LPVOID pRemoteImage = VirtualAllocEx(pi.hProcess, (PVOID)0x400000, peSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, pRemoteImage, maliciousPE, peSize, NULL);

// Resume the hollowed process to execute the malicious code
ResumeThread(pi.hThread);
```

### **APC Injection (Asynchronous Procedure Call Injection)**
   - **APC injection** involves queueing an **asynchronous procedure call (APC)** into an existing thread of a process, which causes the thread to execute the APC (which could be your payload).
   - **Key Characteristics**:
     - Use `QueueUserAPC` to queue an APC (your code or shellcode) into the thread of a target process.
     - When the thread enters an alertable state (i.e., waiting for input or sleeping), it will execute the APC.
     - It is often used to inject code without creating a new thread or hijacking the context directly.
   - **Relation to the Code Above**: The code that injects shellcode into a process via **APC** and queues the shellcode to be executed when a thread enters an alertable state would fall under **APC injection**.

### Example of **APC Injection** in C++:
```cpp
// Example of APC injection to queue shellcode execution in a thread

HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);

// Queue the shellcode as an APC to the target thread
QueueUserAPC((PAPCFUNC)shellcodeAddress, hThread, NULL);

// The shellcode will execute when the thread enters an alertable state (e.g., via SleepEx or WaitForMultipleObjectsEx)
```

### Summary of Techniques and Code Relations:

1. **Thread Hijacking**:
   - Modify an **existing thread's context** to force it to execute injected code.
   - Typically involves suspending the thread, changing its **instruction pointer (EIP/RIP)**, and resuming the thread.
   - **Code example**: Using `GetThreadContext`, `SetThreadContext`, and `SuspendThread/ResumeThread` to hijack a thread.

2. **Process Hollowing**:
   - Start a legitimate process in a **suspended state**, hollow out its memory, and inject your malicious code.
   - The process then resumes execution, running your code in the context of the original process.
   - **Code example**: Using `CreateProcess`, `NtUnmapViewOfSection`, `VirtualAllocEx`, `WriteProcessMemory`, and `ResumeThread` to hollow out and replace the legitimate process.

3. **APC Injection**:
   - Queue an **APC** into a thread’s execution queue to execute your shellcode when the thread enters an alertable state.
   - **Code example**: Using `QueueUserAPC` to inject shellcode into a target process.

### Which Is Stealthier?
- **Thread hijacking** and **APC injection** can be very stealthy, especially when used on trusted or system processes (e.g., `explorer.exe`). They rely on manipulating existing threads rather than creating new ones, which reduces detection by EDR.
- **Process hollowing** is also stealthy but may leave a more obvious forensic trace if the hollowed process is analyzed. However, since it uses a legitimate process's ne (e.g., `svchost.exe`), it can evade some detection mechanisms.

Each method has its specific use case, and the choice depends on your goal (e.g., stealth, ease of execution, persistence).