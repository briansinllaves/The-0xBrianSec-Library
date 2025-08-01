### **Pentest Note: DNS Zone Transfer**

---

#### **DNS Zone Transfer Using `dig`**

- **Command:**
  ```bash
  dig axfr <domain_ne> @<ne_server>
  ```

- **Use Case:**
  - **Zone Transfer:** This command attempts a DNS zone transfer, a process where a DNS server shares its entire DNS zone file with another server. In the context of a penetration test, this technique can be used to gather a complete list of DNS records (like subdomains, IP addresses, mail servers, etc.) from a vulnerable DNS server. 

  - **Target Information:** Replace `<domain_ne>` with the domain you want to test, and `<ne_server>` with the specific DNS server's IP address or hostne.

  - **Example:**
    ```bash
    dig axfr example.com @ns1.example.com
    ```

- **Significance:**
  - **Security Check:** Successful DNS zone transfers should be restricted to authorized servers. If a zone transfer is successful during a pentest, it indicates a significant misconfiguration that could leak critical infrastructure details to an attacker.
