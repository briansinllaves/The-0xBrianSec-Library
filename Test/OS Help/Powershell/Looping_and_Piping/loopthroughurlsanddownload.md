### PowerShell Script for Downloading Files from URLs and Organizing by Domain:

```powershell
# Read all URLs from the file
$urls = Get-Content -Path "C:\path\to\urls.txt"

# Loop through each URL
foreach ($url in $urls) {

    # Extract the domain ne from the URL
    $domain = ($url -split '/')[2]

    # Check if the domain folder exists; if not, create it
    if (-not (Test-Path -Path $domain)) {
        New-Item -Path $domain -ItemType Directory
    }

    # Download the file and save it in the appropriate domain folder
    $filene = Split-Path -Leaf $url
    $outputPath = Join-Path -Path $domain -ChildPath $filene
    Invoke-WebRequest -Uri $url -OutFile $outputPath
}
```

### Explanation:

1. **Reading URLs**:
   - `Get-Content` is used to read all the URLs from the `urls.txt` file.

2. **Extracting Domain ne**:
   - `$url -split '/'` splits the URL by `/`, and `[2]` gets the domain part.

3. **Checking and Creating Directory**:
   - `Test-Path` checks if the directory for the domain exists.
   - `New-Item` creates the directory if it doesn't exist.

4. **Downloading the File**:
   - `Split-Path -Leaf $url` gets the file ne from the URL.
   - `Invoke-WebRequest` downloads the file and stores it in the specified domain directory.

### Notes:
- Make sure the `urls.txt` file path is correctly set in the `Get-Content` command.
- The script assumes the URLs in `urls.txt` are in a format where the domain is always the third element when splitting by `/`.
- The script uses `Invoke-WebRequest` for downloading files, which is the PowerShell equivalent of `wget`.