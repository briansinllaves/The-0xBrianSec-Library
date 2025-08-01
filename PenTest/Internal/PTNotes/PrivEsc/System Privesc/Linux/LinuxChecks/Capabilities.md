
## Detection

**Linux VM**

1. Check capabilities on binaries:
   ```bash
   getcap -r / 2>/dev/null
   ```

is used to search for files with capabilities set across the entire root filesystem (`/`), and it suppresses error messages.

2. Note the value of the `cap_setuid` capability.
```
= cap_setuid+ep:

```

cap_setuid: This is a specific capability that allows the program to change its UID (User ID) when executed. Essentially, it can run with different user privileges than the user who launched the executable.
+ep: 

This means "effective" and "permitted." The +ep suffix indicates that the cap_setuid capability is both effective (actively used by the binary) and permitted (allowed to be used by the binary).
## Exploitation

**Linux VM**

1. Exploit using Python:
   ```bash
   /usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
   ```

- **`/usr/bin/python2.6 -c`**:
    
    - This tells the system to execute the Python 2.6 interpreter with the command that follows inside the single quotes.
- **`import os`**:
    
    - This imports the Python `os` module, which provides a way of using operating system dependent functionality like interacting with the process environment.
- **`os.setuid(0)`**:
    
    - This function call changes the current process's user ID to 0, which is the user ID of the root user. Normally, only processes with root privileges can change their UID to 0. However, since `/usr/bin/python2.6` has the `cap_setuid+ep` capability, it grants the Python process the ability to change its UID.
- **`os.system("/bin/bash")`**:
    
    - Executes a system command `/bin/bash` which opens a new shell. Since the Python process’s UID was set to 0 by the previous command, this new bash shell runs with root privileges, effectively giving root access to the user.


2. Enjoy root access.