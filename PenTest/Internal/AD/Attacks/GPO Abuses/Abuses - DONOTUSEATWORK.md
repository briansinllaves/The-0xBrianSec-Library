**GPO Abuses**

1. **Create/alter file type associations, register DDE actions with those associations.**
   - **Policy Location:** `Computer Configuration\Preferences\Control Panel Settings\Folder Options`

2. **Add new local admin account.**
   - **Policy Location:** `Computer Configuration\Preferences\Control Panel Settings\Local Users and Groups`

3. **Deploy a new evil scheduled task (e.g., PowerShell download cradle).**
   - **Policy Location:** `Computer Configuration\Preferences\Control Panel Settings\Scheduled Tasks`

4. **Create and configure new malicious services.**
   - **Policy Location:** `Computer Configuration\Preferences\Control Panel Settings\Services`

5. **Affected computers will download a file from the domain controller.**
   - **Policy Location:** `Computer Configuration\Preferences\Windows Settings\Files`

6. **Update existing INI files.**
   - **Policy Location:** `Computer Configuration\Preferences\Windows Settings\INI Files`

7. **Update specific registry keys to disable security mechanisms or trigger code execution.**
   - **Policy Location:** `Computer Configuration\Preferences\Windows Settings\Registry`

8. **Deploy a malicious shortcut.**
   - **Policy Location:** `Computer Configuration\Preferences\Windows Settings\Shortcuts`

9. **Deploy a malicious MSI. The MSI must be available to the GP client via a network share.**
   - **Policy Location:** `Computer Configuration\Policies\Software Settings\Software installation`

10. **Configure and deploy malicious startup scripts. Can run scripts out of GPO directory, can also run PowerShell commands with arguments.**
    - **Policy Location:** `Computer Configuration\Policies\Windows Settings\Scripts (startup/shutdown)`

11. **Modify local audit settings to evade detection.**
    - **Policy Location:** `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Audit Policy`

12. **Grant a user rights such as logon via RDP, SeDebugPrivilege, load device drivers, seTakeOwnershipPrivilege. Essentially, take over the remote computer without admin privileges.**
    - **Policy Location:** `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`

13. **Alter DACLs on registry keys to create a hard-to-find backdoor.**
    - **Policy Location:** `Computer Configuration\Policies\Windows Settings\Security Settings\Registry`

14. **Manage the Windows firewall to open blocked ports.**
    - **Policy Location:** `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall`

15. **Add UNC path for DLL side loading.**
    - **Policy Location:** `Computer Configuration\Preferences\Windows Settings\Environment`

16. **Copy a file from a remote UNC path.**
    - **Policy Location:** `Computer Configuration\Preferences\Windows Settings\Files`