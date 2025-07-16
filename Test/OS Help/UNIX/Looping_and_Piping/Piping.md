
### Piping Command Output to a Variable and Looping Through Another Command:


```bash
# Get a list of domains (simulated example)
sids=$(dig +short ABCDglb.com)

# Loop through each domain and perform a command (simulated as echo for demonstration)
for domain in $sids; do
    echo "Processing SID for domain $domain" # Replace with actual command
done

# Save specific property (simulated as 'cut' command to extract a part of the string)
echo "$sids" | cut -d ' ' -f1 > dt7.txt
```

### Piping Command Output to Another Command:

In Linux, piping output from one command directly into another is straightforward:

```bash
# Piping command output to another command
ps aux | grep 'process_ne'

# ForEach-Object equivalent in Bash (piping and processing each file)
ls *.txt | while read file; do
    cat "$file"
done
```


### Piping by Property or Value:

In Linux, you can pipe CSV data and process it using tools like `awk` or custom scripts:

```bash
# Example: Import CSV and pipe data to another command
while IFS=',' read -r computerne port; do
    echo "Testing connection to $computerne on port $port"
    nc -zv "$computerne" "$port"
done < notes.txt
```

This script reads each line of `notes.txt`, extracts the `computerne` and `port`, and then performs a network test using `nc` (netcat).

