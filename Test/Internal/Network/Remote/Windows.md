
### **Remote Network Commands**

#### **1. Routing Traffic Between Networks**

- **Add a Static Route for a Specific Subnet**
  - **Command:**
    ```cmd
    route add 10.10.20.0 mask 255.255.255.0 192.168.1.1
    ```
  - **Use Case:** Configures the host to route traffic for a specific subnet (10.10.20.0/24) through a designated gateway (192.168.1.1). This is useful for reaching isolated or segmented networks.

- **View Routing Table**
  - **Command:**
    ```cmd
    route print
    ```
  - **Use Case:** Verifies that the routing table contains the correct routes for communication across different subnets.

#### **2. Proxying Traffic to Access Isolated Subnets**

- **Using SSH to Tunnel Traffic**
  - **Command:**
    ```cmd
    plink.exe -D 9050 user@remote-server
    ```
  - **Use Case:** Establishes a SOCKS proxy to route traffic through a remote server, enabling access to isolated networks that are not directly reachable.

- **Using ProxyChains**
  - **Command:**
    ```cmd
    proxychains nmap -sT 10.10.20.0/24
    ```
  - **Use Case:** Forces nmap (or other tools) to use a SOCKS proxy, useful for scanning and interacting with isolated subnets.

#### **3. Bypassing Firewalls and Network Restrictions**

- **Pivoting Through Compromised Hosts**
  - **Command:**
    ```cmd
    plink.exe -L 8080:target-internal:80 user@pivot-server
    ```
  - **Use Case:** Forwards traffic from your local machine to an internal target service through a compromised host. This allows you to access services within another network segment.

- **Using `netsh` for Port Forwarding**
  - **Command:**
    ```cmd
    netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.1.100
    ```
  - **Use Case:** Configures port forwarding on a Windows host to redirect traffic from one port to another IP and port. This can be used to forward traffic to a service running on a different network or to bypass firewall restrictions.

- **Example Configuration:**
  - Forward incoming traffic on port 8080 to a web server on `192.168.1.100`:
    ```cmd
    netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.1.100
    ```
  - This allows you to access the web server on `192.168.1.100` by connecting to `localhost:8080`.

#### **4. Accessing Hosts in Other Subnets**

- **Configuring Network Interfaces**
  - **Command:**
    ```cmd
    netsh interface ip set address ne="Ethernet" static 10.10.20.5 255.255.255.0
    ```
  - **Use Case:** Changes the IP address of a network adapter to communicate with a different subnet. This is useful when moving laterally within a segmented network.

- **Example Configuration:**
  - To communicate between `192.168.1.0/24` and `10.10.20.0/24`, add a route and assign an IP in the `10.10.20.0/24` range to the appropriate interface:
    ```cmd
    route add 10.10.20.0 mask 255.255.255.0 192.168.1.1
    netsh interface ip set address ne="Ethernet" static 10.10.20.5 255.255.255.0
    ```

#### **5. Using VPN to Join Remote Networks**

- **Connecting to a VPN**
  - **Command:**
    ```cmd
    rasdial "VPN Connection ne" /phonebook:C:\Path\To\VPN\Phonebook.pbk
    ```
  - **Use Case:** Establishes a VPN connection to a remote network, making it possible to access resources as if you were directly connected to the network.

#### **6. Discovering Other Subnets**

- **IP Routing Information from Hosts**
  - **Command:**
    ```cmd
    route print
    ```
  - **Use Case:** View routing paths to determine if other subnets can be accessed from the current host. This helps in identifying other segments within the network that may be reachable.

#### **7. Determining Access Controls and ACLs**

- **Check Windows Firewall Rules**
  - **Command:**
    ```cmd
    netsh advfirewall firewall show rule ne=all
    ```
  - **Use Case:** Lists all Windows Firewall rules to understand access controls and possible restrictions between network segments.

- **Check Local Security Policies**
  - **Command:**
    ```cmd
    secpol.msc
    ```
  - **Use Case:** Accesses the Local Security Policy editor to review settings that affect network access, such as IPsec policies.

### **Scenario: Moving from Network A (Host A) to Network B (Host B)**

**Objective:** You've compromised `Host A` in `Network A` and need to access `Host B` in `Network B`, which is segmented.

1. **Identify Network Information:**
   - Use `ipconfig /all` and `route print` on `Host A` to identify current subnets and gateways.
   
2. **Determine Network Paths:**
   - Use `tracert` to check if `Host B` or `Network B` is reachable directly from `Host A`. If not, identify potential pivot points.

3. **Set Up Routing:**
   - If `Network B` is reachable via a known gateway, use `route add` to set up a static route.
   - Example:
     ```cmd
     route add 10.10.30.0 mask 255.255.255.0 192.168.1.1
     ```
   - This route directs traffic for `Network B` (`10.10.30.0/24`) through a gateway in `Network A`.

4. **Pivoting Through Hosts:**
   - If `Host A` has access to a machine that can reach `Network B`, set up port forwarding using `plink` or `netsh` to tunnel traffic:
     ```cmd
     plink.exe -L 3389:hostb:3389 user@pivot-server
     ```
     - Or, using `netsh`:
     ```cmd
     netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=hostb-ip
     ```
   - This allows you to access services on `Host B` from `Host A` through the pivot server.

5. **Use VPN or Proxy:**
   - If `Network B` is accessible only via VPN, connect `Host A` to the VPN using:
     ```cmd
     rasdial "VPN Connection ne" /phonebook:C:\Path\To\VPN\Phonebook.pbk
     ```
   - Route traffic to `Host B` through the VPN connection.

A `.pbk` file (Phonebook file) is used by the Windows built-in VPN client to store information about VPN connections, such as server addresses, protocols, and other settings. To obtain or create a `.pbk` file, follow these steps:

### **1. Create a VPN Connection Manually**
- **Step 1:** Open the **Network and Sharing Center**.
- **Step 2:** Click on **Set up a new connection or network**.
- **Step 3:** Select **Connect to a workplace** and click **Next**.
- **Step 4:** Choose **Use my Internet connection (VPN)**.
- **Step 5:** Enter the VPN server address and other details, then click **Create**.

After creating the VPN connection, the connection details will be saved, and you can access them through the `.pbk` file.

### **2. Locate the `.pbk` File**
- **Step 1:** Press `Win + R`, type `explorer %APPDATA%\Microsoft\Network\Connections\Pbk\`, and press `Enter`.
- **Step 2:** This will open the folder where the `.pbk` file is stored. If you've created multiple VPN connections, the file will contain details for each.

### **3. Open and Edit the `.pbk` File**
- **Step 1:** Open the `.pbk` file with a text editor (e.g., Notepad).
- **Step 2:** You can view or edit the VPN connection settings within this file. Be cautious when editing this file to avoid corrupting the VPN configuration.

### **4. Use the `.pbk` File with `rasdial`**
Once you have the `.pbk` file, you can use it with the `rasdial` command to connect to the VPN:
```cmd
rasdial "VPN Connection ne" /phonebook:"C:\Path\To\VPN\Phonebook.pbk"
```
Replace `"VPN Connection ne"` with the ne of the VPN profile you want to use.

### **5. Deploying `.pbk` Files Across Multiple Systems**
If you need to distribute the VPN configuration across multiple systems, you can copy the `.pbk` file to the same location (`%APPDATA%\Microsoft\Network\Connections\Pbk\`) on those systems, and users can connect using the `rasdial` command as shown above.

This approach allows an attacker or pentester to programmatically connect to a VPN using pre-configured settings, which is essential for automated scripts or scenarios where interactive setup is not possible.