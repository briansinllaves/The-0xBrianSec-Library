### Tools and Techniques for Finding Subdomains

1. **Sublist3r**:
   - Enumerates subdomains from various sources.
   - Example:
     ```bash
     sublist3r -d example.com -o subdomains.txt
     ```

2. **CRT.sh**:
   - Finds subdomains via SSL certificates issued for the domain.
   - Example:
     - Visit [crt.sh](https://crt.sh) and search for `%.example.com` to list subdomains.

3. **DNSRecon**:
   - Performs DNS reconnaissance to gather DNS records.
   - Example:
     ```bash
     dnsrecon -d example.com -a -t std,srv -o dnsrecon_results.txt
     ```

4. **DNSDumpster**:
   - An online tool to gather DNS records and subdomains.
   - Example:
     - Visit [dnsdumpster.com](https://dnsdumpster.com) and enter the domain for detailed DNS information.

5. **SecurityTrails**:
   - Uses the SecurityTrails API to gather subdomains and DNS information.
   - Example:
     ```bash
     curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains"
     ```