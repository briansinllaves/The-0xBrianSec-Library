#### **Commands**
Linux commands are often simple, with a structure that includes the command ne followed by options (flags) and arguments. The command ne typically represents the action, and the arguments represent the target resource or input.

**Example Commands:**
- `ls`: Lists directory contents.
- `cp`: Copies files or directories.
- `mv`: Moves or renes files or directories.
- `grep`: Searches text using patterns.

#### **Common Commands with Their Actions**
- **`touch`**: Creates a new empty file.
- **`cp`**: Copies an existing file or directory.
- **`mv`**: Moves or renes a file or directory.
- **`cat`**: Reads and displays the content of a file.
- **`find`**: Searches for files and directories based on a given condition.
- **`grep`**: Searches within files for matching text patterns.
- **`ps`**: Displays information about running processes.
- **`bash`**: Executes commands or scripts.

#### **Options (Parameters)**
Each Linux command can be followed by various options (often called flags) that modify its behavior. Options refine how the command operates, such as specifying detailed output, recursive operations, or case sensitivity.

**Examples:**
- `ls -l`: Lists directory contents in long format, showing detailed information.
- `grep -i`: Searches text in a case-insensitive manner.
- `find / -ne "file.txt"`: Searches the entire filesystem for "file.txt".

#### **Piping and Redirection**
In Linux, the output of one command can be passed (piped) to another command for further processing, much like PowerShell. This allows for chaining commands together to perform complex operations.

**Example:**
- `ps aux | grep "chrome"`: Finds all running processes related to "chrome".
- `cat file.txt | grep "error" > errors.txt`: Searches for the word "error" in `file.txt` and redirects the output to `errors.txt`.

#### **Objects**
In Linux, the output of commands is usually text (stdout) rather than objects. However, this text output can be manipulated or processed by other commands in the pipeline.

**Example:**
- `ls -l | awk '{print $9}'`: Lists all files in a directory and then uses `awk` to print only the filenes.
