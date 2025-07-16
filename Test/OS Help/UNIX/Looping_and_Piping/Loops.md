Use a `for` loop to iterate over a range with more control:

```bash
# For Loop in Bash
for i in {1..98}; do
   echo "17.165.1.$i"
done
```
This generates IP addresses from "17.165.1.1" to "17.165.1.98".

### **ForEach Loop**
Use a `for` loop to iterate over a collection in Bash (since Bash doesn't have a direct `ForEach` equivalent):

```bash
# Assuming you have a list of users in a file or variable
users=("John Doe" "Jane Smith" "Bob Johnson")

for user in "${users[@]}"; do
    firstne=$(echo $user | cut -d ' ' -f1)
    lastne=$(echo $user | cut -d ' ' -f2)
    echo "$firstne.$lastne@smith.com"
done
```
This loop iterates over each user in the list and constructs an email address using their first and last nes.

### **ForEach-Object Equivalent**
In Bash, to process each item in a pipeline:

```bash
# Example: Output just the HotfixID for each installed hotfix
# (Assuming you have a command that outputs Hotfix information in a similar format)

# Simulated example: processing each line of a file
cat hotfixes.txt | while read line; do
    echo "$line" | cut -d ' ' -f1  # Assuming HotfixID is the first field
done
```

This loop processes each line of the file `hotfixes.txt` and outputs the first field, which is treated as the `HotfixID` in this example.