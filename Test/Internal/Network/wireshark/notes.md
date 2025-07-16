### **Pentest Note: Wireshark for Network Analysis**

Wireshark is an essential tool for network analysis during pentests. Below are key features and filters that can assist in analyzing captured network traffic.

---

### **Key Wireshark Features**

---

#### **Resolved Addresses**

- **Path:** `Statistics` -> `Resolved Addresses`
  - **Use Case:** Displays the resolved IP addresses and their corresponding MAC addresses or domain nes. Useful for identifying devices and services in the network.

---

#### **Expert Information**

- **Path:** `Analyze` -> `Expert Information`
  - **Use Case:** Provides a summary of potential issues, warnings, and notable events in the packet capture. Useful for quickly identifying anomalies or critical security events.

---

#### **Protocol Hierarchy**

- **Path:** `Statistics` -> `Protocol Hierarchy`
  - **Use Case:** Shows the distribution of different protocols in the capture. Helps in identifying the types of traffic and protocols most prevalent in the network.

---

#### **Conversations**

- **Path:** `Statistics` -> `Conversations`
  - **Use Case:** Summarizes the conversations between IP addresses. Useful for identifying key communication channels and potential targets for further investigation.

---

#### **Endpoints**

- **Path:** `Statistics` -> `Endpoints`
  - **Use Case:** Provides details about each endpoint involved in the network capture, including IP, MAC addresses, and packet statistics. Helps in identifying devices and their activity levels.

---

#### **DNS Information**

- **Path:** `Statistics` -> `DNS`
  - **Use Case:** Shows DNS queries and responses, which can reveal internal domain nes, external connections, and potential misconfigurations.

---

#### **I/O Graph**

- **Path:** `Statistics` -> `I/O Graph`
  - **Use Case:** Visual representation of traffic over time. Useful for spotting spikes in activity, which could correlate with attacks or other significant network events.

---

#### **BOOTP/DHCP**

- **Path:** `Statistics` -> `BOOTP/DHCP`
  - **Use Case:** Shows DHCP traffic, which can reveal new devices joining the network or devices obtaining IP addresses. This is useful for tracking potential rogue devices.

---

#### **Search**

- **Path:** Press `CTRL+F` to search for specific content inside the packets.
  - **Use Case:** Quickly locate specific strings, IP addresses, or protocols within the packet capture.

---

### **Additional Wireshark Filters for Pentesting**

---

#### **HTTP and Domain Identification**

- **Filter:**
  - **Command:**
    ```plaintext
    http.host
    ```
  - **Use Case:** Identify HTTP hosts and domains. Apply as a column to easily see domain nes in the HTTP traffic.

---

#### **SSL/TLS Handshake**

- **Filter:**
  - **Command:**
    ```plaintext
    ssl.handshake.type == 1
    ```
  - **Use Case:** Shows SSL/TLS handshake packets, useful for identifying the server ne (SNI) and initial connection attempts. This can help identify the target's HTTPS services.

---

#### **Kerberos Authentication**

- **Filter:**
  - **Command:**
    ```plaintext
    kerberos
    ```
  - **Use Case:** Filters out Kerberos-related traffic, useful for analyzing authentication requests and responses in environments that use Kerberos for authentication.

---

#### **NTLM Authentication**

- **Filter:**
  - **Command:**
    ```plaintext
    ntlmssp
    ```
  - **Use Case:** Isolates NTLM authentication traffic, useful for identifying NTLM challenge/response sequences, which can be used for cracking or replay attacks.

---

#### **Cloud Service Identification**

- **Filter:**
  - **Command:**
    ```plaintext
    ip.addr == <cloud_ip> && tcp.port == 443
    ```
  - **Use Case:** Filters out traffic to known cloud service IP ranges, focusing on HTTPS traffic. Useful for analyzing interactions with cloud-based services.

---

#### **SMB Traffic**

- **Filter:**
  - **Command:**
    ```plaintext
    smb || smb2
    ```
  - **Use Case:** Focuses on SMB traffic, which is essential for analyzing file-sharing activities, potential SMB relay attacks, and other Windows-related network shares.

---

#### **DNS Query Filter**

- **Filter:**
  - **Command:**
    ```plaintext
    dns.qry.ne contains "domain"
    ```
  - **Use Case:** Filters DNS queries containing specific domain nes. Useful for tracking down domains being queried by the target network, which could reveal C2 domains or external services.

---

### **Customizing Columns in Wireshark**

- **How to:**
  - **Right-click on any packet field** in the packet details pane and choose `Apply as Column`.
  - **Use Case:** Customize Wireshark to display relevant fields, such as domain nes, IP addresses, or specific protocol details, making it easier to analyze the traffic at a glance.

---
