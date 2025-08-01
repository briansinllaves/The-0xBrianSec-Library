### **Pentest Note: Network Protocol Abuse and Coercion Techniques**

---

### **LLMNR / NBT-NS / mDNS Poisoning**


### **IPv6 Preference over IPv4**

- **mitm6 Attack:**
  - **Command:**
    ```bash
    mitm6 -d <domain>
    ```
  - **Use Case:** Exploits IPv6 preference in networks to perform Man-in-the-Middle (MITM) attacks by spoofing DNS and DHCPv6 responses, capturing or relaying credentials.

---

### **ARP Poisoning with Bettercap GUI**

- **Using Bettercap2 GUI:**
  - **Instructions:**
    1. **Start Bettercap2:**
       - Run Bettercap2 on your machine with GUI enabled.
       - **Command:**
         ```bash
         sudo bettercap -caplet http-ui
         ```
    2. **Access the GUI:**
       - Open a web browser and navigate to `http://<your_ip>:8081`.
    3. **Enable ARP Spoofing:**
       - In the Bettercap GUI, go to the **Modules** section.
       - Enable the **arp.spoof** module by toggling it on.
    4. **Specify Targets:**
       - Set your target(s) by entering their IP addresses in the **Target** field or let it spoof the entire network.
    5. **Start Spoofing:**
       - Click on **Start** to begin ARP poisoning, which will redirect traffic from the target(s) through your machine.

  - **Use Case:** Intercepts traffic between devices on the network, allowing you to capture sensitive data or perform MITM attacks.
