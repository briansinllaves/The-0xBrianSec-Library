### Fuzzing Web Directories with FFUF, Nikto, DirBuster, and DirSearch

#### FFUF Command
```bash
ffuf -u https://GLOBAL-MERGER-CHARTS-FE.AZUREWEBSITES.NET/FUZZ -w /opt/SecLists/Discovery/Web-Content/big.txt -r -e .txt,.html,.js,.css,.xml,.aspx,.asp -o ./output.txt -fc 200,201
```

- **`-u https://GLOBAL-MERGER-CHARTS-FE.AZUREWEBSITES.NET/FUZZ`**: Target URL with `FUZZ` placeholder.
- **`-w /opt/SecLists/Discovery/Web-Content/big.txt`**: Path to the wordlist.
- **`-r`**: Recursion option.
- **`-e .txt,.html,.js,.css,.xml,.aspx,.asp`**: File extensions to fuzz.
- **`-o ./output.txt`**: Output file.
- **`-fc 200,201`**: Filter out HTTP status codes 200 and 201.

This command can reveal WAF behavior if every request returns a status code 200.

#### Nikto Command
```bash
nikto -h https://GLOBAL-MERGER-CHARTS-FE.AZUREWEBSITES.NET
```
- **`-h https://GLOBAL-MERGER-CHARTS-FE.AZUREWEBSITES.NET`**: Target host to scan.

#### DirBuster Usage
1. **Start DirBuster**:
   ```bash
   java -jar /path/to/DirBuster-1.0-RC1.jar
   ```
2. **Set the Target URL**: Enter `https://GLOBAL-MERGER-CHARTS-FE.AZUREWEBSITES.NET` in the target URL field.
3. **Configure Options**:
   - **Wordlist**: Select `/opt/SecLists/Discovery/Web-Content/big.txt`.
   - **Extensions**: Add `.txt,.html,.js,.css,.xml,.aspx,.asp`.

#### DirSearch Command
```bash
dirsearch -u https://GLOBAL-MERGER-CHARTS-FE.AZUREWEBSITES.NET -w /opt/SecLists/Discovery/Web-Content/big.txt -e txt,html,js,css,xml,aspx,asp
```
- **`-u https://GLOBAL-MERGER-CHARTS-FE.AZUREWEBSITES.NET`**: Target URL.
- **`-w /opt/SecLists/Discovery/Web-Content/big.txt`**: Path to the wordlist.
- **`-e txt,html,js,css,xml,aspx,asp`**: File extensions to scan for.

### Fuzzing Splash Pages
Mary wants to fuzz splash pages such as:
- "Welcome to nginx"
- IIS welcome pages
- Red Hat welcome pages

These splash pages often indicate default installations or misconfigurations that can be further explored for vulnerabilities. Use the above tools to identify such pages and then manually inspect them for further details.