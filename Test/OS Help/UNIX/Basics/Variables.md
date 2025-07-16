### **Basics of Variables in Linux**

- **Variables in Bash:** In Bash, variables are assigned without a `$` prefix. However, to reference the value of a variable, you prefix it with a `$`.
  
  ```bash
  # Create a variable
  tmol=42
  
  # Access the value of the variable
  echo $tmol
  ```

- **Data Storage:** Variables can store strings, numbers, command output, and more.

#### **Special Variables in Bash**

- **`$?`**: Represents the exit status of the last command executed (0 for success, non-zero for failure).
- **`$0`**: Represents the ne of the script or command being executed.
- **`$#`**: Represents the number of positional parameters passed to the script.
- **`$@`**: Represents all the positional parameters as separate strings.
- **`$*`**: Represents all the positional parameters as a single string.
- **`$$`**: Represents the process ID of the current shell.
- **`$!`**: Represents the process ID of the last background command.

#### **Storing Contents in a Variable**

To store the contents of a file into a variable in Bash:

```bash
list=$(cat computers.txt)
```

- **Explanation:** 
  - `list=$(cat computers.txt)` reads the contents of `computers.txt` into the variable `list`.

### **Creating, Listing, and Deleting Variables in Bash**

- **Create a Variable:**

  ```bash
  # Creating a variable and assigning a value
  tmol=42
  ```

  This creates a variable `tmol` and assigns it the value `42`.

- **List All Variables:**

  To list all currently defined variables:

  ```bash
  # List all environment variables
  printenv
  
  # Or, to list all shell variables, use:
  set
  ```

  - **Explanation:** 
    - `printenv` lists all environment variables.
    - `set` lists all shell variables, including functions.

- **Delete a Variable:**

  To delete or unset a variable:

  ```bash
  unset tmol
  ```

  - **Explanation:** 
    - `unset tmol` removes the variable `tmol` from the session.