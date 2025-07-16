
The `RDPScanner` is a tool for discovering and testing RDP services across multiple hosts. It can handle numerous connections in parallel and provide detailed feedback on authentication attempts. 

### **Key Functionalities:**

1. **Target List Initialization**:
   - The application can take a single target host or a list of targets from a file. Each target represents an IP address or hostne where an RDP service might be running.
   - If a target includes a port (e.g., `192.168.1.100:3389`), it will use that port; otherwise, it defaults to port 3389, which is the standard port for RDP.

2. **Parallel Processing**:
   - It supports concurrent scanning by using multiple threads. You can specify the number of threads to run in parallel through the `/threads` argument.
   - Each thread will handle RDP connections independently, which speeds up the scanning process.

3. **RDP Connection Setup**:
   - For each target, the program configures an RDP client using the `AxMsRdpClient9NotSafeForScripting` COM object, which is part of the Microsoft RDP ActiveX control.
   - It sets up various connection parameters, including the server address, port, userne, password, and whether to use Network Level Authentication (NLA).

4. **Event Handling**:
   - The application listens for different events such as connection completion, logon errors, and disconnection. Based on these events, it provides feedback about the status of each connection attempt.
   - On a successful connection, it will print a success message and disconnect from the session.
   - It logs errors and reasons for disconnections, which helps in understanding connection issues.

5. **User Interaction**:
   - The RDP client runs in a hidden form to avoid user interaction with the graphical interface.
   - This allows the program to run in the background while testing connections.

#### **Scanning a Single RDP Server:**

```bash
RDPScanner.exe /host:192.168.1.100 /user:domain\\userne /password:password /nla
```

- **`/host:192.168.1.100`**: The IP address of the RDP server.
- **`/user:domain\\userne`**: The userne in the `domain\userne` format. Use double backslashes to escape the backslash.
- **`/password:password`**: The password for the specified user.
- **`/nla`**: Indicates that Network Level Authentication should be used.

#### **Scanning Multiple RDP Servers from a File:**

```bash
RDPScanner.exe /file:targets.txt /user:domain\\userne /password:password /nla /threads:10
```

- **`/file:targets.txt`**: A file containing a list of IP addresses or hostnes, one per line.
- **`/threads:10`**: Uses 10 threads for concurrent scanning.

### **Additional Considerations**

- **Permissions**: Ensure that you have permission to scan and test RDP connections on the targets. Unauthorized scanning or testing could be illegal or against network policies.
- **Network Security**: Be mindful of network security policies and legal implications when running such tools.
