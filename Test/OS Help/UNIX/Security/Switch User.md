### 1. **Using `sudo` to Run a Command as Another User:**
   - The `sudo` command allows you to run a command as another user, including root. You typically need to have permission to use `sudo` for the target user.

   ```bash
   sudo -u userne command
   ```

   - **Example:**

     ```bash
     sudo -u john ls /home/john
     ```

   - This will run the `ls` command in the `/home/john` directory as the user `john`.

### 2. **Using `su` to Switch to Another User:**
   - The `su` command is used to switch to another user account and then execute commands as that user.

   ```bash
   su - userne -c "command"
   ```

   - **Example:**

     ```bash
     su - john -c "ls /home/john"
     ```

   - This will execute the `ls` command in the `/home/john` directory as the user `john`.

### 3. **Using `sudo` with a Shell:**
   - To open a shell as another user, you can use `sudo` with a shell command.

   ```bash
   sudo -u userne -s
   ```

   - **Example:**

     ```bash
     sudo -u john -s
     ```

   - This will start a shell as the user `john`.

### 4. **Running Graphical Applications as Another User:**
   - If you need to run a graphical application as another user, you can still use `sudo` or `su`.

   ```bash
   sudo -u userne application_ne
   ```

   - **Example:**

     ```bash
     sudo -u john gedit /home/john/somefile.txt
     ```

### Notes:
- **`sudo`**: You may need to have sudo privileges for the target user or be in the `sudoers` group.
- **`su`**: You need to know the password of the target user unless you're switching to root.
