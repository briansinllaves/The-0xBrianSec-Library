
 ### **COM Hijacking for Persistence in Penetration Testing**

COM (Component Object Model) hijacking allows attackers to maintain persistence on a system by redirecting legitimate COM object calls to malicious payloads via registry manipulation. Here’s how to detect and exploit this technique.

### **Procmon Filters to Detect COM Hijacking**

To detect potential COM hijacking, use these filters in Procmon:

- **Detecting `InprocServer32` Hijacks:**
  - **Operation:** `RegOpenKey`
  - **Path Ends With:** `InprocServer32`
  - **Path Contains:** `HKCU\Software\Classes\CLSID`
  - **Process ne:** `vulnprogram.exe`
  - **Result:** `nE NOT FOUND`
  - **Integrity Level:** `High`

- **Detecting `LocalServer32` Hijacks:**
  - **Operation:** `RegOpenKey`
  - **Path Ends With:** `LocalServer32`
  - **Path Contains:** `HKCU\Software\Classes\CLSID`
  - **Process ne:** `vulnprogram.exe`
  - **Result:** `nE NOT FOUND`
  - **Integrity Level:** `High`

- **Detecting `TreatAs` Hijacks:**
  - **Operation:** `RegOpenKey`
  - **Path Contains:** `TreatAs`
  - **Path Contains:** `HKCU\Software\Classes\CLSID`
  - **Process ne:** `vulnprogram.exe`
  - **Result:** `nE NOT FOUND`
  - **Integrity Level:** `High`

- **Detecting `ProgID` Hijacks:**
  - **Operation:** `RegOpenKey`
  - **Path Contains:** `ProgID`
  - **Path Contains:** `HKCU\Software\Classes`
  - **Process ne:** `vulnprogram.exe`
  - **Result:** `nE NOT FOUND`
  - **Integrity Level:** `High`

### **Exploitation Steps**

1. **Identify CLSID or ProgID:**
   - Use Regedit or Procmon to find the CLSID or ProgID associated with the target process.

stop capture, trash can and 
start process capture
run tool 
pause capture
Grab clsid
 ![[Pasted image 20230202184849.png]]
Create a clsid and a reg key
 ![[Pasted image 20230202184856.png]]

2. **Create Malicious COM Component:**
   - Write a malicious DLL or EXE. Use tools like PowerShell to create a DLL that bypasses antivirus.
     - **Example:** Create a DLL with PowerView or Nishang that executes malicious code.

3. **Modify Registry:**
   - Redirect `InprocServer32`, `LocalServer32`, `TreatAs`, or `ProgID` keys to point to your malicious component.
   
Add value to point to .dll in user writeable space “i.e desktop” then dll will write to c:\windows. 

right click on inprocserver32 and add string data “Both” to Thread modeling
![[Pasted image 20230202184902.png]]
  

4. **Trigger the Hijack:**
   - Execute the target program, which will now load your malicious component.
   
Check c:windows for new text
![[Pasted image 20230202184909.png]]
 
 ![[Pasted image 20230202184913.png]]
Must use admin cmd to remove

### **Defensive Measures**

- **Monitor Registry Changes:** Regularly audit critical registry keys related to COM objects.
- **Application Whitelisting:** Prevent execution of unauthorized DLLs and EXEs.
- **Behavioral Analysis:** Use tools to detect unusual COM activity, such as unexpected DLL/EXE loads.

