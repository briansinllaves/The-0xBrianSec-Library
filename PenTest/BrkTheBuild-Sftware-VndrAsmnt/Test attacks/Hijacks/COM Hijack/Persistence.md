### **Wininet Cache Task Scheduled Task Exploit**

**Summary:**
A scheduled task, `CacheTask`, located under `C:\Windows\System32\Tasks\Microsoft\Windows\Wininet\CacheTask`, can be triggered upon user logon without requiring user interaction. This task was identified on Windows 10 and can be leveraged for persistence or privilege escalation.

**Details:**

- **Task Location:**  
  The configuration files for all scheduled tasks are stored in the `C:\Windows\System32\Tasks` directory. The specific task in focus is the `Wininet CacheTask` located at:
  ```plaintext
  C:\Windows\System32\Tasks\Microsoft\Windows\Wininet\CacheTask
  ```

- **ClassID:**  
  This task is associated with the ClassID:
  ```plaintext
  {0358B920-0AC7-461F-98F4-58E32CD89148}
  ```

- **DLL Used:**  
  When invoked, the task utilizes the `wininet.dll` located in:
  ```plaintext
  c:\windows\system32\wininet.dll
  ```

**Potential Exploit:**

This task is triggered by a user logon event, meaning it can be exploited without any direct user interaction. If you can manipulate or replace the DLL (`wininet.dll`) that this task invokes, you could potentially execute malicious code under the context of the user or even with elevated privileges, depending on the task's configuration.

**Mitigation:**

To protect against exploitation:

- **Monitor Task Modifications:** Regularly monitor the `C:\Windows\System32\Tasks\Microsoft\Windows\Wininet\CacheTask` for unauthorized changes.
- **Integrity Checks:** Implement integrity checks for critical DLLs like `wininet.dll` to ensure they haven’t been tampered with.
- **Review Task Permissions:** Ensure that only trusted users and processes have the permissions to modify scheduled tasks and their associated DLLs.
The task has the {0358B920–0AC
7–461F-98F4–58E32CD89148} ClassID and uses the c:\windows\system32\wininet.dll when invoked:



We can find it in HKLM, beat the search order by adding it in HKCU.


Created in HKCU, add CLSID, right-click add New> key, add your payload.

Right click add new string or expanded string value.


At User login, catowner.txt will be in ProgramData. Whoami is executed and the output is the written in the document. 

the CacheTask may not be in the TaskScheduler.  

check procmon boot logging