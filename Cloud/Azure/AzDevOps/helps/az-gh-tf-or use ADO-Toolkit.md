### Title: Azure DevOps Lo
### Title: Finding Personal Access Tokens (PATs) in Variables and URLs

### Steps to Find PATs in Variables

1. **Inspect URL**:
   - Look for potential PATs in the URL or variable values.

2. **Identify Patterns for PATs**:
   - PATs are typically 52 characters long.
   - They may follow a specific pattern, such as lowercase and numbers, or lowercase and uppercase (but not both together).

### Regular Expressions for Matching PATs

1. **Pattern 1: Lowercase and Numbers**
   ```regex
   [a-z0-9]{52}
   ```

2. **Pattern 2: Lowercase and Uppercase**
   ```regex
   [a-zA-Z]{52}
   ```

### Example: Searching for GitHub Tokens
```shell
# Example GitHub token format
ghp_asdfwe
```

### Script for Finding PATs in Variables
```powershell
# Define a regex pattern for PATs
$regexPattern = "[a-z0-9]{52}|[a-zA-Z]{52}"

# Function to search for PATs in a given string
function Find-PATs {
    param (
        [string]$inputString
    )
    
    if ($inputString -match $regexPattern) {
        Write-Output "Found PAT: $($matches[0])"
    } else {
        Write-Output "No PAT found in the input."
    }
}

# Example usage
$variables = @("somevariablevalue1234567890abcdefghijklmnopqrstuvwxyz1234567890abcd", "ghp_asdfwe")

foreach ($variable in $variables) {
    Find-PATs -inputString $variable
}
```

### Using the Script to Find PATs in URLs
1. **Extract URL/Variable Content**:
   - Use the script to scan the content of URLs or variables for PATs.

2. **Output the Results**:
   - The script will output any found PATs based on the defined regex patterns


   
### Title: Extracting and Testing Variables After Terraform Login

### Steps to Extract Variables and Dump Azure Pipeline Data

1. **Login to Terraform**:
   - Log in to Terraform and grab additional variables.

2. **Dump Azure Pipeline Data**:
   - Use a tool to dump Azure pipeline data, focusing on secrets and artifacts.

3. **Inspect Paths in Pipeline**:
   - Check the paths for specific patterns.

### Regex Patterns for Paths and Tokens

1. **Path Tokens**:
   - Regex for path tokens: 
     ```regex
     [a-zA-Z0-9/\\-]{52}
     ```

2. **Base64 Encoded Strings**:
   - Regex for Base64 strings starting with a semicolon (;) and capital 'O':
     ```regex
     ;O[a-zA-Z0-9+/]{50}
     ```

### Script to Test Against Variable Dumps

1. **Extract and Test Variables**:
   ```powershell
   # Define regex patterns
   $pathTokenPattern = "[a-zA-Z0-9/\\-]{52}"
   $base64Pattern = ";O[a-zA-Z0-9+/]{50}"

   # Function to search for tokens and Base64 strings in variables
   function Test-Variables {
       param (
           [string]$inputString
       )
       
       if ($inputString -match $pathTokenPattern) {
           Write-Output "Found Path Token: $($matches[0])"
       } elseif ($inputString -match $base64Pattern) {
           Write-Output "Found Base64 String: $($matches[0])"
       } else {
           Write-Output "No match found in the input."
       }
   }

   # Example variable dumps
   $variableDumps = @(
       "examplepath/token1234567890abcdefghijklmnopqrstuvwxyz1234567890",
       ";OabcdefghijklmnopqrstuvwxyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=="
   )

   # Test each variable dump
   foreach ($variable in $variableDumps) {
       Test-Variables -inputString $variable
   }
   ```

2. **Checking Secrets and Artifacts**:
   - Use the script to scan secrets and artifacts in the dumped pipeline data.

### Notes on Extracting and Testing Variables
- **Focus on Sensitive Data**: Ensure to inspect all paths and variable dumps for sensitive data such as tokens and Base64 encoded strings.
- **Regex Matching**: Use the defined regex patterns to accurately match and extract relevant data.
