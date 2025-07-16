```# Interactive Find and Replace Script in PowerShell

# Prompt the user for file path
$filePath = Read-Host "Enter the file path"

# Check if the specified file exists
if (-Not (Test-Path -Path $filePath -PathType Leaf)) {
    Write-Output "Error: File not found at $filePath"
    exit
}

# Prompt user for the string to find
$findString = Read-Host "Enter the string to find"

# Check if the findString is in the file
$content = Get-Content -Path $filePath
if ($content -notcontains $findString) {
    Write-Output "The string '$findString' was not found in the file."
    exit
} else {
    Write-Output "The string '$findString' was found in the file."
}

# Prompt user to enter the replacement string
$replaceString = Read-Host "Enter the replacement string"

# Replace the findString with the replacement string in the file
$contentUpdated = $content -replace [regex]::Escape($findString), $replaceString

# Write the updated content back to the file
Set-Content -Path $filePath -Value $contentUpdated

# Confirm the replacement was made
Write-Output "The string '$findString' has been replaced with '$replaceString' in the file '$filePath'."
```
