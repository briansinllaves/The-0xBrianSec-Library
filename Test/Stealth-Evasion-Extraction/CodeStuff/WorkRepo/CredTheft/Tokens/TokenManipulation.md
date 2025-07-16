** Run With Admin

### Summary:
This program interacts with Windows processes and tokens, allowing the user to list process tokens, steal tokens from processes or threads, and potentially launch a new process with a duplicated token. It can also set a stolen token to the current process. The tool uses arguments to either list tokens, steal process tokens, or manipulate thread tokens.

### CLI Usage:
- `/list:all` – Lists all process tokens.
- `/steal:<PID>` – Steals a token from the specified process ID (PID).
- `/stealthread:<TID>` – Steals a token from the specified thread ID (TID).
- `/process:<exe>` – Specifies the executable to run with the stolen token (e.g., `cmd`).

### Example CLI Usage:
```
TokenTool.exe /list:all
TokenTool.exe /steal:1234 /process:cmd
```