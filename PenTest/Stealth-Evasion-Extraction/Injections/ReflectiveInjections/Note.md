**Reflective injection** is another common and powerful technique for loading and executing code directly in memory. It doesn't rely on writing the payload to disk and is used for **stealthy in-memory execution** of PEs (Portable Executables, such as EXEs or DLLs). This technique can also evade traditional security mechanisms, as it doesn’t involve the typical file-loading routines that AV/EDR often monitor.

Reflective injection can be used in two common forms:
- **Reflective PE Injection**: Loading and executing an entire Portable Executable (PE) such as an EXE or DLL into memory.
- **Reflective DLL Injection**: Loading a DLL into memory without using the `LoadLibrary` function, which is normally used by Windows to load DLLs.

Reflective injection **differs** from techniques like **process hollowing**, **thread hijacking**, and **APC injection**, but it **can be combined** with them for more advanced and stealthier operations.

**Reflective injection** involves manually loading a PE file (either an EXE or DLL) into the memory space of a process and executing it directly from memory without ever touching the disk. It bypasses the normal Windows loader mechanisms like `LoadLibrary` (for DLLs) or `CreateProcess` (for EXEs).

Here’s how it works in general:
1. **Allocate Memory in the Target Process**: Allocate memory for the payload within the target process.
2. **Reflective Loader**: A custom loader parses the PE headers (EXE or DLL) from memory, relocates the code, resolves any imports, and calls the PE's entry point.
3. **Execution**: The loaded PE runs entirely in memory.

Reflective injection is particularly useful in:
- **Reflective DLL Injection**: Injecting DLLs into a process without using the `LoadLibrary` function.
- **Reflective PE Injection**: Injecting EXEs or custom payloads entirely in memory without creating a new process on disk.

### Why Reflective Injection Isn't in the List Above
Reflective injection is **different from** thread hijacking, process hollowing, or APC injection because those techniques involve manipulating existing processes or threads. Reflective injection is more focused on **how the payload (EXE/DLL) is loaded into memory** and executed, regardless of whether it is done via process injection or another method.

You can **combine reflective injection with techniques like process hollowing, thread hijacking, or APC injection** to achieve stealthy, in-memory execution. For example:
- You might use **thread hijacking** to force a thread to execute a **reflectively loaded** PE.
- You can use **process hollowing** to create a suspended process and then **inject reflectively loaded code** into its memory space.

### How Reflective PE and DLL Injection Work

#### Reflective DLL Injection
In **reflective DLL injection**, the DLL is loaded directly into memory using a custom loader, which mimics what `LoadLibrary` normally does. The loader parses the DLL's headers, resolves its imports, and relocates the code to the correct memory location.

**Reflective DLL Injection Process**:
1. **Memory Allocation**: Allocate memory in the target process for the DLL.
2. **Copy DLL to Memory**: Copy the DLL (which resides in memory) to the allocated memory space.
3. **Custom Reflective Loader**:
   - Parse the **PE headers** to locate the DLL’s sections, imports, and entry point.
   - **Relocate** the sections to match the memory layout.
   - **Resolve imports** by locating necessary functions from other DLLs.
   - Call the DLL’s **entry point (e.g., DllMain)** to initialize the loaded DLL.

**Reflective DLL Injection Example Code**:
```cpp
void ReflectiveDLLInjection(HANDLE hProcess, unsigned char* dllBuffer, SIZE_T dllSize) {
    // Allocate memory in the target process
    LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Write the DLL to the allocated memory
    WriteProcessMemory(hProcess, pRemoteBuffer, dllBuffer, dllSize, NULL);

    // Create a remote thread to call the reflective loader in the DLL
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
}
```
**Usage**: The **dllBuffer** contains the DLL in memory, and the reflective loader will be executed to load the DLL in memory without `LoadLibrary`.

#### Reflective PE Injection
In **reflective PE injection**, the goal is to load a full **EXE** or **PE file** directly into memory and execute it without touching the disk.

**Reflective PE Injection Process**:
1. **Memory Allocation**: Allocate memory for the PE in the target process.
2. **PE Parsing**:
   - Parse the **PE headers** to understand the layout of the executable.
   - Copy the necessary sections (e.g., `.text`, `.data`) to memory.
   - Handle **relocations** if the PE is loaded at a different memory address than expected.
   - **Resolve imports** by mapping the required functions from system libraries (e.g., `kernel32.dll`).
3. **Execution**: After loading the PE and setting up the environment, call the **entry point** of the PE (which could be a `main()` function or another code section).

**Reflective PE Injection Example Code**:
```cpp
void ReflectivePEInjection(HANDLE hProcess, unsigned char* peBuffer) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)peBuffer;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(peBuffer + dosHeader->e_lfanew);
    
    // Allocate memory in the target process
    LPVOID baseAddress = VirtualAllocEx(hProcess, NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Copy PE headers to allocated memory
    WriteProcessMemory(hProcess, baseAddress, peBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);
    
    // Copy PE sections to allocated memory
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)(peBuffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        WriteProcessMemory(hProcess, (BYTE*)baseAddress + sectionHeader->VirtualAddress, peBuffer + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData, NULL);
    }

    // Create remote thread to execute the PE's entry point
    LPTHREAD_START_ROUTINE entryPoint = (LPTHREAD_START_ROUTINE)((BYTE*)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    CreateRemoteThread(hProcess, NULL, 0, entryPoint, NULL, 0, NULL);
}
```

### How Reflective Injection Fits with Other Techniques

- **Reflective Injection + Process Hollowing**: You could use **reflective PE injection** to inject code into a hollowed process, making it look like the legitimate process is running, but with malicious code.
  
- **Reflective Injection + Thread Hijacking**: You could inject a **reflectively loaded PE** and hijack an existing thread to execute it. This can make the injection even stealthier since no new threads are created.

- **Reflective Injection + APC Injection**: Reflectively inject a DLL into memory and then use **APC injection** to queue the execution of its entry point into an existing thread, minimizing detection.

### Summary

- **Reflective Injection** is a stealthy technique used to load and execute **PEs** (EXEs/DLLs) directly in memory without using traditional methods like `LoadLibrary` or `CreateProcess`. It bypasses disk and API-based monitoring mechanisms that EDRs and AV systems often rely on.
- **Reflective DLL Injection** and **Reflective PE Injection** both achieve similar outcomes (loading PEs into memory), but they differ in terms of payloads (DLL vs. EXE).
- Reflective injection can be combined with **thread hijacking**, **process hollowing**, and **APC injection** to make the operation stealthier and harder to detect.

Reflective injection is a **stealthier and more advanced method** of executing payloads compared to direct execution or typical process injection techniques like using `CreateRemoteThread` or `LoadLibrary`.