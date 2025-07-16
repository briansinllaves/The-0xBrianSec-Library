- **Selecting Specific Properties:** Use `awk` or `cut`.

- **Filtering Based on Conditions:** Use `grep` and `awk`.
- **Complex Filtering:** Combine `grep` and `awk` to refine results.

#### **Selecting Specific Properties (Equivalent to `Select-Object`)**

To select specific columns from command output in Linux, you can use `awk` or `cut`.

**Example: Select the `ne` and `Status` of running services:**

```bash
# Using `ps` to list processes and `awk` to select specific columns
#prints the first column (`User`) and the eleventh column (`Command`).
ps aux | awk '{print $1, $11}'
```


#### **Filtering Based on Conditions (Equivalent to `Where-Object`)**

You can filter command output based on conditions using `grep`, `awk`, or `find`.

**Example: Get running services (processes):**

```bash
ps aux | grep 'running'
```

**Filter processes with "chrome" in their ne:**

```bash
ps aux | grep 'chrome'
```

**Filter command results to show only specific types (e.g., aliases in a Linux context could be listing alias commands):**

```bash
alias | grep 'alias_ne'
```

#### **Complex Filtering**

To perform more complex filtering, you can combine conditions with `grep` and `awk`.

**Example: Filter running services that have "win" in their ne:**

```bash
ps aux | grep 'win' | grep 'running'
```

- **Explanation:**
  - This chain of commands first filters the process list to those containing "win" and then further filters them to show only those that are running (you can adjust the grep to match the specific pattern indicating a running process).


