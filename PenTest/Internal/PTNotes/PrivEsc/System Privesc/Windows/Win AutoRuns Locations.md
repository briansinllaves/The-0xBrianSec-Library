### **Autoruns Locations for Windows**

When performing a pentest or forensic analysis, it's essential to identify where autoruns (programs that start automatically) are configured on a Windows system. These autoruns can be located in various registry keys, file system locations, scheduled tasks, and service configurations. Below is a comprehensive guide to these locations.

---

#### **Registry Locations**

1. **Current User (Affects Only the Logged-In User)**
   - **Run:**
     - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
   - **RunOnce:**
     - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`

2. **Local Machine (Affects All Users)**
   - **Run:**
     - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
   - **RunOnce:**
     - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`
   - **RunServices:**
     - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices`
   - **RunServicesOnce:**
     - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`

3. **Legacy AutoRun Locations**
   - **Setup:**
     - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup`
   - **Userinit:**
     - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
   - **Shell:**
     - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`

---

#### **File System Locations**

1. **Startup Folder (Current User)**
   - `%USERPROFILE%\Start Menu\Programs\Startup`

2. **Startup Folder (All Users)**
   - `%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup`

---

#### **Scheduled Tasks**

- **Task Scheduler Library:**
  - Accessed via the Task Scheduler application.
  - Files can be found at: `C:\Windows\System32\Tasks`

---

#### **Services and Drivers**

1. **Windows Services**
   - **Services Configured to Start Automatically:**
     - Managed via `services.msc`
     - Registry location: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`

2. **Driver Services**
   - **Drivers Configured to Start Automatically:**
     - Found in the same registry location as services.

---

#### **Other Locations**

1. **Group Policy**
   - **Startup Applications Configured via Group Policy:**
     - Managed via `gpedit.msc`
     - Can affect multiple users or the entire machine.

2. **Browser Extensions**
   - **AutoRun Configurations in Browsers:**
     - Internet Explorer, Edge, Chrome, and Firefox may have their own autorun settings for extensions and add-ons.
