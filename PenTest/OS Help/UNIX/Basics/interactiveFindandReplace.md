```


#!/bin/bash

# Prompt user for file path
echo -n "Enter the file path: "
read FILE_PATH

# Check if the specified file exists
if [ ! -f "$FILE_PATH" ]; then
    echo "Error: File not found at $FILE_PATH"
    exit 1
fi

# Prompt user for the string to find
echo -n "Enter the string to find: "
read FIND_STRING

# Check if the find_string is in the file
if grep -q "$FIND_STRING" "$FILE_PATH"; then
    echo "The string '$FIND_STRING' was found in the file."
else
    echo "The string '$FIND_STRING' was not found in the file."
    exit 1
fi

# Prompt user to enter the replacement string
echo -n "Enter the replacement string: "
read REPLACE_STRING

# Replace the find_string with the replacement string in the file
sed -i "s/$FIND_STRING/$REPLACE_STRING/g" "$FILE_PATH"

# Confirm the replacement was made
echo "The string '$FIND_STRING' has been replaced with '$REPLACE_STRING' in the file '$FILE_PATH'."

```

```
chmod +x interactive_find_replace.sh
./interactive_find_replace.sh
```