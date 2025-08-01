
ProcessChecker

- **Compile as 64-bit**: If your injector or checker is targeting 64-bit processes, you need to compile it as a 64-bit application to properly interact with 64-bit processes.
- **Compile as 32-bit**: If you're targeting 32-bit processes, you can compile as 32-bit.

1st run
```
tasklist /v
tasklist /m /FI "IMAGEnE eq credwiz.exe"
```

if modules have wow64 then 32 bit


- Run with 
```
precheck.exe notepad.exe

precheck.exe 1234  # where 
1234 is the PID

```




```
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>

// Function to find the process ID from the process ne
DWORD FindProcessId(const std::wstring& processne) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (std::wstring(pe.szExeFile) == processne) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return 0;
}

// Function to check if the process is 32-bit or 64-bit
void CheckArchitecture(HANDLE hProcess) {
    BOOL isTargetWow64 = FALSE;
    IsWow64Process(hProcess, &isTargetWow64);

    if (isTargetWow64) {
        std::cout << "Target process is 32-bit." << std::endl;
    } else {
        SYSTEM_INFO systemInfo;
        GetNativeSystemInfo(&systemInfo);
        if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
            std::cout << "Target process is 64-bit." << std::endl;
        } else {
            std::cout << "Target process is 32-bit." << std::endl;
        }
    }
}

// Function to get free memory in the target process
void GetFreeMemory(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = nullptr;
    SIZE_T totalFreeMemory = 0;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_FREE) {
            totalFreeMemory += mbi.RegionSize;
        }
        address = (LPVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
    }

    std::cout << "Total free memory in the target process: " << totalFreeMemory / (1024 * 1024) << " MB" << std::endl;
}

// Function to check memory permissions in the target process
void CheckMemoryPermissions(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = nullptr;

    std::cout << "Memory permissions in target process:" << std::endl;
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
            std::cout << "Writable and executable memory found at address: " << mbi.BaseAddress << std::endl;
        }
        address = (LPVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
    }
}

// Function to check for known security software processes
void CheckSecuritySoftware() {
    std::vector<std::wstring> securityProcesses = { L"MsMpEng.exe", L"avp.exe", L"wrsa.exe", L"mbam.exe", L"avgnt.exe" };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot." << std::endl;
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    std::cout << "Checking for security software..." << std::endl;
    if (Process32First(hSnapshot, &pe)) {
        do {
            for (const auto& secProc : securityProcesses) {
                if (std::wstring(pe.szExeFile) == secProc) {
                    std::cout << "Security software detected: " << secProc << std::endl;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: <program.exe> <pid|process_ne>" << std::endl;
        return 1;
    }

    DWORD processId = 0;

    // Check if the argument is a number (PID)
    if (iswdigit(argv[1][0])) {
        processId = _wtoi(argv[1]);
    } else {
        processId = FindProcessId(argv[1]);
        if (processId == 0) {
            std::cerr << "Process not found." << std::endl;
            return 1;
        }
    }

    // Open the target process with necessary permissions
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Failed to open target process." << std::endl;
        return 1;
    }

    // Check architecture compatibility
    CheckArchitecture(hProcess);

    // Get free memory in target process
    GetFreeMemory(hProcess);

    // Check memory permissions
    CheckMemoryPermissions(hProcess);

    // Check for security software that might block injection
    CheckSecuritySoftware();

    CloseHandle(hProcess);
    return 0;
}

```

