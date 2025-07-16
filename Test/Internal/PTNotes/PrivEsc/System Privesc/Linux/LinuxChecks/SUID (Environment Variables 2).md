
## Detection

**Linux VM**

1. List all SUID binaries:
   ```bash
   find / -type f -perm -04000 -ls 2>/dev/null
   ```
   ![[Pasted image 20240917212233.png]]
2. Check the functions used by the binary:
   ```bash
   strings /usr/local/bin/suid-env2
   ```

3. Note the functions.


## Exploitation Method #1

**Linux VM**

1. Create a function to escalate privileges:
   ```bash
   function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }

   ```

This defines a **shell function** ned `/usr/sbin/service` (overriding the legitimate `service` command) that:

1. **Copies** `/bin/bash` to `/tmp`.
2. **Sets the SUID bit** on `/tmp/bash` with `chmod +s`, allowing it to run with root privileges when executed.
3. **Executes** `/tmp/bash` with the `-p` flag, which retains the effective user ID (root in this case), giving a **root shell**.

2. Export the function:
   ```bash
   export -f /usr/sbin/service
   ```

This **exports** the function, making it available in the environment for any processes run by the shell (like the SUID binary). This is critical because when the SUID binary (`/usr/local/bin/suid-env2`) calls `/usr/sbin/service`, it will use the **malicious function** instead of the legitimate service executable.
the `export` step ensures that the SUID binary uses the attacker's custom function to escalate privileges and create a root shell.


3. Run the SUID binary:
   ```bash
   /usr/local/bin/suid-env2
   ```

![[Pasted image 20240917220050.png]]

4. Return the function back to default
```
This command removes the function definition for `/usr/sbin/service`, restoring the default behavior of the real `service` command.

unset -f /usr/sbin/service

**Check if the function is removed**:

type /usr/sbin/service
```


## Exploitation Method #2

**Linux VM**

1. Exploit using environment variables:
   ```bash
   env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'
   ```

![[Pasted image 20240917212540.png]]
This command leverages environment variables and the SUID binary (`/usr/local/bin/suid-env2`) to escalate privileges using a clever combination of shell options and tracing functionality.

### Breakdown of how it works:

1. **`env -i`**: 
   - Runs the command with a completely empty environment (no inherited environment variables).
   
2. **`SHELLOPTS=xtrace`**: 
   - `SHELLOPTS` is a special environment variable in bash that sets shell options. In this case, `xtrace` is set, which enables command tracing (`set -x`). This makes bash print each command it executes, prefixed by `PS4`.

3. **`PS4='$(...)'`**: 
   - `PS4` is the prompt printed before each command when `xtrace` is enabled. Here, `PS4` is being set to execute a command using `$(...)`.
   - The command inside `PS4` is: 
     ```bash
     cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash
     ```
     This creates a copy of `/bin/bash` in `/tmp`, changes its ownership to root, and sets the SUID bit (`chmod +s`). The SUID bit allows the new bash shell (`/tmp/bash`) to run with root privileges when executed.

4. **`/bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'`**:
   - **`/bin/sh -c`**: This runs the commands within quotes (`'/usr/local/bin/suid-env2; set +x; /tmp/bash -p'`).
   - **`/usr/local/bin/suid-env2`**: This is the SUID binary that runs with elevated privileges (root in this case). Since `SHELLOPTS=xtrace` is set, bash will trace commands executed within this context, and because `PS4` is hijacked, the command inside `PS4` (copying and modifying `/bin/bash`) will be executed with root privileges.
   - **`set +x`**: Turns off tracing, so commands are no longer printed.
   - **`/tmp/bash -p`**: Executes the newly created SUID root shell (`/tmp/bash`) with the `-p` flag, preserving the root privileges.

### Privilege Escalation Flow:
- By setting `SHELLOPTS=xtrace` and hijacking the `PS4` prompt, the command in `PS4` is executed each time the shell traces a command.
- When the SUID binary (`/usr/local/bin/suid-env2`) runs, it runs with root privileges, and since the shell is in tracing mode, the `PS4` command (`cp /bin/bash /tmp && chmod +s /tmp/bash`) is executed as root.
- This results in the creation of a root-owned bash shell with the SUID bit set. Once `/tmp/bash -p` is executed, it gives you a root shell.




2. Clean up
```
rm /tmp/bash
unset SHELLOPTS
unset PS4

ls -l /tmp


```