#### **Splitting a String (Equivalent to `Split`)**

**Example: Split content from a file by `:` and get the second part**

Suppose you have a file `dt2.txt` with the following content:

```plaintext
ne:John
department:Engineering
location:New York
```

**Using `cut`:**

```bash
# Using `cut` to split by `:` and get the second field
cut -d':' -f2 dt2.txt
```

**Output:**

```plaintext
John
Engineering
New York
```

- **Explanation:** 
  - `cut -d':' -f2 dt2.txt` splits each line in `dt2.txt` by the colon (`:`) delimiter and outputs the second field.
  

**Using `awk`:**

```bash
# Using `awk` to split by `:` and print the second part
awk -F':' '{print $2}' dt2.txt
```

**Output:**

```plaintext
John
Engineering
New York
```

- **Explanation:** 
  - `awk -F':' '{print $2}' dt2.txt` tells `awk` to use `:` as the field separator and prints the second field.

#### **Expanding and Returning a Property (Equivalent to `ExpandProperty`)**

**Example: Get the `department` property from a file where the department starts with "E":**

Suppose you have a file `ad_users.txt` with the following content:

```plaintext
ne:John
department:Engineering
location:New York

ne:Jane
department:Marketing
location:San Francisco

ne:Jim
department:Engineering
location:Boston
```

**Using `grep` and `awk`:**

```bash
# Using `grep` to filter and `awk` to extract the department starting with "E"
grep '^department' ad_users.txt | awk -F':' '$2 ~ /^E/ {print $2}'
```

**Output:**

```plaintext
Engineering
Engineering
```

- **Explanation:** 
  - `grep '^department' ad_users.txt` filters lines that start with "department".
  - `awk -F':' '$2 ~ /^E/ {print $2}'` uses `:` as a field separator, matches departments starting with "E", and prints the department ne.

**Using `jq` (if working with JSON data):**

Suppose you have a JSON file `ad_users.json` with the following content:

```json
[
    {"ne": "John", "department": "Engineering", "location": "New York"},
    {"ne": "Jane", "department": "Marketing", "location": "San Francisco"},
    {"ne": "Jim", "department": "Engineering", "location": "Boston"}
]
```

```bash
# Using `jq` to filter and return the `department` property from JSON data
jq '.[] | select(.department | startswith("E")) | .department' ad_users.json
```

**Output:**

```plaintext
"Engineering"
"Engineering"
```

- **Explanation:** 
  - `jq '.[] | select(.department | startswith("E")) | .department' ad_users.json` filters the JSON array for objects where the `department` starts with "E" and returns the `department` value.
