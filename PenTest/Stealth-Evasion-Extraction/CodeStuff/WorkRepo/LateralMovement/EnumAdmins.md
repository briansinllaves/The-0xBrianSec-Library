The `EnumAdmins.exe` program queries a specified Windows server to enumerate two sets of information: 
1. the members of the local "administrators" group 
2. the currently logged-on users. 
It uses the `NetLocalGroupGetMembers` API to list administrators and the `NetWkstaUserEnum` API to get details about logged-in users. The results are written to a specified log file or, by default, to `C:\\Tools\\Bginfo.dat`. If the log file is not provided, it defaults to the predefined path.

### **Usage:**

To use the program, run it from the command line with the following arguments:

```
EnumAdmins.exe \\Serverne [LogFile]
```

- **`\\Serverne`**: The ne of the target server. Ensure to use double backslashes (`\\`) as the server ne prefix.
- **`[LogFile]`** *(optional)*: The path to the log file where the results will be saved. If omitted, the default log file path is `C:\\Tools\\Bginfo.dat`.

**Example Command:**

```
EnumAdmins.exe \\MyServer C:\\Logs\\admin_report.txt
```

This command will query `MyServer`, enumerate the members of the local "administrators" group and the currently logged-on users, and save the results to `admin_report.txt` in the `C:\\Logs\\` directory.