### Summary:

Running this tool will require **administrator (elevated)** privileges due to the need for SE Debug privileges.

This program duplicates the token from a process specified by its process ID (PID) and spawns a new process (default: `cmd.exe`) with the duplicated token. 

It requires SE Debug privileges to manipulate the process tokens. The tool enables the SE Debug privilege and attempts to duplicate the token from the given PID.

### CLI Usage:

- Provide the process ID (PID) of the target process as an argument.

### Example CLI Usage:

```
duptoken.exe 1234
```

This will duplicate the token from the process with PID `1234` and spawn a new `cmd.exe` using that token. 