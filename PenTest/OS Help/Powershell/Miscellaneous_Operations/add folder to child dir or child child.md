Here’s how to convert the provided Unix shell script to PowerShell:

### PowerShell Script to Add a "dns" Subdirectory to All Subdirectories:

```powershell
# Define the path to the parent directory
$parentDir = "C:\path\to\parentdir"

# Get all subdirectories within the specified parent directory
$subDirs = Get-ChildItem -Path $parentDir -Directory

# Loop through each subdirectory and create a "dns" subdirectory within it
foreach ($dir in $subDirs) {
    $dnsDir = Join-Path -Path $dir.Fullne -ChildPath "dns"
    
    # Create the "dns" subdirectory if it doesn't exist
    if (-not (Test-Path -Path $dnsDir)) {
        New-Item -Path $dnsDir -ItemType Directory
    }
}
```

### Explanation:

1. **Path Definition**:
   - The `$parentDir` variable specifies the directory where you want to add the "dns" subdirectory to each subdirectory.

2. **Get-ChildItem**:
   - `Get-ChildItem -Path $parentDir -Directory` retrieves all immediate subdirectories within the specified parent directory.

3. **Join-Path**:
   - `Join-Path -Path $dir.Fullne -ChildPath "dns"` constructs the full path for the "dns" subdirectory within each subdirectory.

4. **Test-Path**:
   - `Test-Path` checks if the "dns" subdirectory already exists before creating it.

5. **New-Item**:
   - `New-Item -Path $dnsDir -ItemType Directory` creates the "dns" subdirectory.

### Notes:
- This script will only add the "dns" subdirectory to immediate child directories of the specified parent directory.
- The script ensures that the "dns" directory is only created if it does not already exist.