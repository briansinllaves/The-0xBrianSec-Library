```
#!/bin/bash
# Reading each line of a file and performing an action
while IFS= read -r line; do
    echo "Processing $line"
done < file.txt
```