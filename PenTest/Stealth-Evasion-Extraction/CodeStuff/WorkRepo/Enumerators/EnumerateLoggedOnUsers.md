This C# code enumerates logged-on users on a remote or local system using WMI. It filters out `DWM` (Desktop Window Manager sessions) and `UMFD` (User-Mode Font Driver Host), which are system processes associated with graphical and font rendering. The code retrieves `Win32_LoggedOnUser` and `Win32_LogonSession`, parses user data, and maps logon sessions to users.

### How to Execute:
1. **Local execution:**
   ```bash
   EnumerateLoggedOnUsers.exe <Computerne> <Userne> <Password>
   ```

2. **Remote execution example:**
   ```bash
   EnumerateLoggedOnUsers.exe 192.168.1.10 domainUser password321
   ```

This example queries the remote system at `192.168.1.10` with the credentials of `domainUser` and `password321`.