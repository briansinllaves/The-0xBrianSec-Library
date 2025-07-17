### **Filtering Instances in Linux**

Assume you have a list of instances stored in a file or produced by a command.

#### **Example with `grep`:**

If you have a file `instances.txt` that contains a list of instances:

```plaintext
instance1_bri
instance2_other
brianora_instance3
instance4
```

You can filter lines that contain "bri" using the following `grep` command:

```bash
# Using grep to filter instances that match the pattern 'bri'
filteredInstances=$(grep -E 'bri' instances.txt)
```

- **Explanation:**
  - `grep -E 'bri' instances.txt` searches for the pattern `bri` in the file `instances.txt`.
  - The `-E` flag is used for extended regular expressions, but in this case, it's optional since we're only looking for a simple pattern.

#### **Example with `awk`:**

Alternatively, you can use `awk` for more complex pattern matching:

```bash
# Using awk to filter instances that match the pattern 'bri'
filteredInstances=$(awk '/bri/' instances.txt)
```

- **Explanation:**
  - `awk '/bri/' instances.txt` searches each line in `instances.txt` for the pattern `bri` and prints the matching lines.

### **Example Output:**

If `instances.txt` contains the following:

```plaintext
instance1_bri
instance2_other
brianora_instance3
instance4
```

**Using the `grep` or `awk` command above, the `filteredInstances` variable would contain:**

```plaintext
instance1_bri
brianora_instance3
```

### Filtering Output with a Condition:

In Linux, the `grep` command is commonly used to filter output based on a condition:

```bash
# Filtering processes by ne
ps aux | grep 'notepad'

# Showing properties and methods (simulated by listing details of a file or command output)
ls -l somefile | awk '{print $1, $2, $3}'
```

### Accessing and Displaying Specific Properties:

To access specific properties of a command output:

```bash
# Simulating accessing a specific property of a command's output
user=$(getent passwd lara)
carlicense=$(echo "$user" | awk -F':' '{print $5}') # Example: extracting a specific field

# Access the property directly
echo "$carlicense"
```
