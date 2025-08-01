**Pentest Notes: Proxies and Pivoting**

### Setting Up Local and Remote SSH SOCKS Proxy

**Step 1: Set Up Local SSH SOCKS Proxy**
- Command: On your local machine, set up an SSH tunnel that acts as a SOCKS proxy.
  
  ```bash
  ssh -D 1080 -C -q -N [user]@[local-ssh-server-ip]
  ```

  - `-D 1080`: Specifies that the SOCKS server will run locally on port 1080.
  - `-C`: Enables compression.
  - `-q`: Enables quiet mode, reducing log output.
  - `-N`: Tells SSH that no command will be executed once the tunnel is established.
  - Replace `[user]` with your userne and `[local-ssh-server-ip]` with the IP address of your SSH server that will host the SOCKS proxy.

**Step 2: Set Up Remote SSH SOCKS Proxy**
- Command: On another server, set up another SSH tunnel.
  
  ```bash
  ssh -D 1081 -C -q -N [user]@[remote-ssh-server-ip]
  ```

  - This command is similar to the first but runs on a different local port (1081) and connects to a different server (`[remote-ssh-server-ip]`).

**Step 3: Configure Proxychains**
- Configuration: Edit your `proxychains.conf` file to chain these two SOCKS proxies.

  ```plaintext
  [ProxyList]
  socks5 127.0.0.1 1080
  socks5 [remote-ssh-server-ip] 1081
  ```

  - The first line in the `ProxyList` section tells Proxychains to use the local SOCKS proxy set up on port 1080.
  - The second line directs Proxychains to use the remote SOCKS proxy set up through the remote SSH session.

**Step 4: Run Applications through Proxychains**
- Usage: To run an application through Proxychains, use the following command:

  ```bash
  proxychains [application] [options]
  ```

  - Replace `[application]` with the ne of the application you want to run through the proxy chain.
  - Replace `[options]` with any command line options the application requires.

### Considerations

**Security**
- Ensure that your SSH sessions are secure by using key-based authentication and by keeping your private keys safe.

**Performance**
- Using multiple SSH SOCKS proxies can significantly affect the performance of your network traffic, as it introduces latency and bandwidth overhead.

**Testing**
- Test the setup with different applications to ensure that traffic is being routed as expected and that applications are functioning correctly through the proxy chain.

### How Proxies Route Data

**Connection Flow and Data Routing**

1. **Initial Request from Your Application:**
   - When you run an application through Proxychains configured with multiple proxies, the application sends its network request to the first proxy in your configuration list.
   - This network request includes the ultimate destination address (the final server you want to reach on the internet).

2. **Handling by the First Proxy:**
   - The first proxy (the local SSH SOCKS proxy running on your machine) receives the request from your application.
   - This proxy connects to the second proxy in the list and forwards the request along. Importantly, the request still contains the final destination's address.

3. **Receipt by the Second Proxy:**
   - The second proxy (set up on the remote host via SSH) receives the request from the first proxy.
   - The SOCKS protocol used by the SSH tunneling provides the necessary information to maintain the original destination information through the proxy chain.

4. **Connection to the Final Destination:**
   - Using the destination information preserved in the request it received, the second proxy establishes a connection to the final destination server.
   - It forwards the original request data to this destination server.

**How SOCKS Maintains Destination Information**

- **SOCKS Protocol:** SOCKS is designed to forward packets between a client and a server through a proxy server. It supports both TCP (for most web traffic) and UDP (used for streaming and gaming).
- **Connection Setup:** During the SOCKS connection setup phase, the client tells the proxy the destination hostne and port number it wants to connect to.
- **Protocol Handling:** SOCKS proxies do not modify the content of the data passing through them. Each proxy forwards the data based on its setup protocols.

### Bypassing Firewalls with Proxies

**Routing Through Non-Restricted Paths**

1. **Using Open Ports:**
   - Proxies can route traffic through ports allowed by the firewall, such as HTTP (port 80) or HTTPS (port 443).
   - Outbound connections are generally allowed more liberally than inbound connections.

2. **Encapsulating Traffic:**
   - **Tunneling:** Proxies can use tunneling mechanisms like SSH tunnels with SOCKS proxies to encapsulate traffic in protocols allowed by the firewall.
   - **Encrypted Connections:** By encrypting the connection between the client and the proxy, firewalls that perform packet inspection cannot determine the nature or destination of the encapsulated traffic.

**IP Address Masquerading**

- The real destination IP addresses are hidden from the local network and the firewall. The firewall only sees the IP address of the first proxy in the chain.

**Chaining Multiple Proxies**

- **Layered Hopping:** Using multiple proxies in a chain complicates traceability from the source to the final destination.
- **Dynic IP Addressing:** Rotating proxies or using dynic IP ranges can evade IP-based blacklists.

### Summary

Proxies, especially when used in chains and combined with techniques like tunneling and encryption, provide powerful methods for bypassing firewalls. They obscure the origin and content of internet traffic, navigate around port and IP restrictions, and use allowed communication protocols to transmit blocked or filtered content. This method is commonly used in environments where internet access is restricted or monitored, offering a means to access information or services without being blocked or logged by network security systems.