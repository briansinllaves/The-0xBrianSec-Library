

### PowerShell Script to Remove Contents of Child Directories:

```powershell
# Define the path to the target directory
$path = "C:\targets\global\empt\americas"

# Get all child directories within the specified path
$childDirs = Get-ChildItem -Path $path -Directory -Recurse

# Loop through each child directory and remove its contents
foreach ($dir in $childDirs) {
    # Remove all files and directories within the current child directory
    Get-ChildItem -Path $dir.Fullne -Recurse | Remove-Item -Force -Recurse
}
```

### Explanation:

1. **Path Definition**:
   - The `$path` variable specifies the directory where you want to remove the contents of child directories.

2. **Get-ChildItem**:
   - `Get-ChildItem -Path $path -Directory -Recurse` retrieves all directories within the specified path, including subdirectories.

3. **Loop and Remove**:
   - The script loops through each child directory and removes all its contents (files and directories) using `Remove-Item -Force -Recurse`.

### Notes:
- **`-Force`** is used to bypass prompts and remove read-only files if any.
- **`-Recurse`** ensures that all nested files and directories are removed within each child directory.
- Be cautious when using this script as it will permanently delete the files and directories.