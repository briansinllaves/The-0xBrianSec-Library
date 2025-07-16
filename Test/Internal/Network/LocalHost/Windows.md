### **Windows Network Pentest Notes**

---

### **Local Network Commands**

#### **1. Check Active TCP Connections**
- **Command:**
  ```cmd
  netstat -an | findstr ESTABLISHED
  ```
- **Use Case:** Lists all established TCP connections to understand ongoing communications on the host.

#### **2. Check Detailed Active Connections**
- **Command:**
  ```cmd
  netstat -ab
  ```
- **Use Case:** Displays all active connections along with the executable involved and their state. Useful for identifying which applications are communicating over the network.

#### **3. Check Open Ports and Associated Applications**
- **Command:**
  ```cmd
  netstat -nb
  ```
- **Use Case:** Shows open ports and the executables associated with them. Helps identify services running on the host.

#### **4. Check Listening Ports**
- **Command:**
  ```cmd
  netstat -ano
  ```
- **Use Case:** Lists all listening ports with their associated process IDs (PIDs). Useful for identifying which services are ready to accept connections.

#### **5. Find Specific Application Ports**
- **Command:**
  ```cmd
  netstat -ano | findstr :80
  ```
- **Use Case:** Filters netstat output to display connections on a specific port, such as port 80 for web services.

#### **6. View Routing Table**
- **Command:**
  ```cmd
  route print
  ```
- **Use Case:** Displays the routing table, which shows the routes the system will take to reach different networks. Important for understanding how traffic is routed within the network.

#### **7. Identify Network Interfaces**
- **Command:**
  ```cmd
  ipconfig /all
  ```
- **Use Case:** Provides detailed information on network interfaces and their configurations, such as IP addresses, gateways, and DNS servers.

#### **8. Determine Gateway and Network Paths**
- **Command:**
  ```cmd
  tracert 8.8.8.8
  ```
- **Use Case:** Maps out the path packets take to reach a target, helping to understand network topology and potential segmentation.

---
