modifications or creations of .manifest and local redirection files, dirs or junctions to cause the program to load a dll.

Schedule task path to dll hijack

Check through schedule task for what is writeable and run elevated.
Runs as system


Found exe 
 



**Look for dlls not found that the exe is looking for**
	
procmon
setup procmon w/ filters:



- **Operation:** `Load Image`
- **Path Contains:** `.dll` and hkcu
- **Result:** `nE NOT FOUND` (indicating the application tried to load a DLL but couldn’t find it)
- **Process ne:** `vulnerableapp.exe`
- **Integrity Level:** `High`

 
pause capture
clear events
start capture
run found schedule task, refresh, wait until ready
pause capture
filter by exe. (right click 'include exe") choose a dll
select filtered ctrl c copy to a .txt as backup
I will choose version.dll
clone exported sys functions and add to your custom dll.

Using program DLLHijacktest.exe
open dllfunctest> dllhijacktest.cpp (to dll function (do a command)test) and DLL LOADER ( the app that loads the dll and tells you the address of where it is loaded as the proof)  in vs

------TEST function----
-- Build dll -- 
in Explorer in the dllhijack solution folder delete .dll, (an old dll from a previous project) and open the dllfunctest to fix the function

change cmd arg to push txt file to
```
c:\\windows\\kissa.txt
```
rebuild
copy location from build output where dll is stored to enter that into loader


-- Load dll --
the dll loader exe is what is going to call or load the dll function into memory
add in the dllfunctestdll address

in the DLL LOADER main loadlibrary addin the dll path from above this should be in the solution folder x64 release next to the loader app, not the program folder.  

```
C:\\Users\\admin\\source\\repos\\Updated8-17-23\\OffsecDev-main\\cpp\\DLLforTest\\DllHijackTest\\x64\\Release\\dllfunctest.dll
```

rebuild solution
Test that a dll function will be called
 

A cmd window will flash
run .\dllloader.exe 



Verify sinllaves.txt is in the c:\windows folder on the vm. Ok its good.

-----
PREP THE DLL BY CLONING Sys32 DLL export functions
prep the dll and change the ne with .\prepdll.bat version. This is the dll "ne not found" (version.dll)
 

uses net clone to clone functions of sys32 dll??

---------------
Move version.dll to host machine

Move dll to dir that is missing dll

Run scheduled task that will trigger dll
Review c:\windows for the kissa.txt that was created. 

Ok it is. Back to procmon

Check for SUCCESS validation of exploitation
 

Success


### **Persistence via DLL Hijacking**

- **Startup Applications:**  
  - Place the hijacked DLL in the directory of an application that runs at startup to ensure your payload executes each time the system starts.

- **Scheduled Tasks:**  
  - Exploit DLL hijacking in applications launched by scheduled tasks that run with elevated privileges, such as SYSTEM or Administrator.

### **Privilege Escalation via DLL Hijacking**

- **High-Privilege Applications:**  
  - Target applications that run with administrative privileges. When your malicious DLL is loaded by such an application, it will execute with the same privileges, potentially allowing for privilege escalation.

- **Service Applications:**  
  - Target services that load DLLs. If a service runs as SYSTEM, hijacking its DLLs can lead to code execution with SYSTEM privileges.

### **Defensive Measures Against DLL Hijacking**

- **DLL Search Order Hardening:**  
  - Use techniques such as `SetDllDirectory(NULL)` to restrict the directories searched for DLLs, thereby reducing the risk of DLL hijacking.

- **Code Signing:**  
  - Implement code signing for all DLLs. Applications can be configured to load only DLLs that are properly signed, mitigating the risk of loading malicious DLLs.

- **Monitor and Audit:**  
  - Regularly audit directories where DLLs are loaded from and monitor for any unauthorized DLLs that could indicate a hijacking attempt.
