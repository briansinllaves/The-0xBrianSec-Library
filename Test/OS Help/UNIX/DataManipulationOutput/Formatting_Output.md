To format output in Linux similar to how PowerShell's `Format-Table` and `Format-List` work, you can use tools like `awk`, `column`, and `printf`. Here’s how you can achieve similar formatting in Linux:

### **Formatting Output in Linux**

#### **Format as a Table**

To format the output as a table in Linux, you can use `awk` in combination with `column`.

**Example: List users from the "Research" department:**

```bash
# Assuming you have a file or command output listing users and their departments
cat users.txt | awk '$2 == "Research" {print $1, $3}' | column -t
```

- **Explanation:**
  - `awk '$2 == "Research" {print $1, $3}'` filters lines where the second column (`$2`) is "Research" and prints the first and third columns (`$1` for ne, `$3` for Enabled).
  - `column -t` formats the output into a neatly aligned table.

#### **Format as a List**

To format output as a list, you can use `awk` or simply echo each property line by line.

**Example: List users with properties as a list:**

```bash
# Assuming you have a file or command output listing users and their properties
cat users.txt | awk '$2 == "Research" {print "ne: "$1"\nEnabled: "$3"\n"}'
```

- **Explanation:**
  - `awk '$2 == "Research" {print "ne: "$1"\nEnabled: "$3"\n"}'` filters the relevant users and formats each user’s details as a list.

### **Example with Hardcoded Data**

If you are working with command output or files, here’s a mock example:

```bash
# Example content in users.txt
# ne    Department    Enabled
# Alice   Research      True
# Bob     Sales         False
# Carol   Research      True

# To format as a table:
awk '$2 == "Research" {print $1, $3}' users.txt | column -t

# To format as a list:
awk '$2 == "Research" {print "ne: "$1"\nEnabled: "$3"\n"}' users.txt
```

This will give you a similar effect to `Format-Table` and `Format-List` in PowerShell but using Linux command-line tools.