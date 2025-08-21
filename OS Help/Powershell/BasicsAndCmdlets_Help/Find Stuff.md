#### Select-String
Use `Select-String` to search for text patterns in files.
Example: Search for "error" in a log file:
```powershell
Select-String -Path "C:\logs\log.txt" -Pattern "error"
```

#### Find all files with a particular ne
```
PS C:\> Get-ChildItem "C:\Users\" recurse -include *passwords*.txt 
```

#### **Recursive Search**:
To search recursively for `.sh` files across all directories:
```powershell
Get-ChildItem -Path "C:\" -Filter "*.sh" -Recurse -ErrorAction SilentlyContinue
```
- **`Get-ChildItem`** (`gci` or `ls` for short) lists items in the directory.
- **`-Path "C:\"`** specifies the starting point (root directory).
- **`-Filter "*.sh"`** limits the search to `.sh` files.
- **`-Recurse`** makes the search recursive.
- **`-ErrorAction SilentlyContinue`** suppresses errors (like "Access Denied").

#### **Non-Recursive Search**:
To find all `.txt` files in the `Desktop` directory without recursion:
```powershell
Get-ChildItem -Path "$HOME\Desktop" -Filter "*.txt" -Depth 1
```
- **`-Depth 1`** limits the search to the current directory level.


#### **Find Multiple File Types (`this` or `that`)**:
To search for `.txt` or `.xml` files on the `Desktop`:
```powershell
Get-ChildItem -Path "$HOME\Desktop" -Filter "*.txt", "*.xml" -Recurse -ErrorAction SilentlyContinue
```
- Lists both `.txt` and `.xml` files in the specified directory recursively.

#### **Find and Execute Command (`-exec` equivalent)**:
To find all `.txt` files and output them with a custom command:
```powershell
Get-ChildItem -Path "$HOME\Desktop" -Filter "*.txt" -Recurse | ForEach-Object {
    Write-Output "Found: $_.Fullne"
    Get-Content $_.Fullne
}
```
- **`ForEach-Object {}`** runs a block of commands for each item found.
- **`Get-Content`** outputs the file content, similar to `cat`.

### **PowerShell Equivalent for `which`**:
To find the path of an executable:
```powershell
Get-Command python3
```
- **`Get-Command`** is the PowerShell equivalent of `which`.
- Finds the location of `python3` (if it’s in the system’s `PATH`).
