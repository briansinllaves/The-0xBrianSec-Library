## Reconnaissance Steps

## 1. **Surface Mapping and Initial Scan**
   - Map the surface.
   - Scan and sort the top 2000 results.
   - Perform IP to domain or reverse conversions.
   - Check the `dig/nslookup` script.
   - Scan IPs.

## 2. **OSINT and IP Block Spaces**
   - Run Amass for OSINT on ASN and IP block spaces.
   - Scan IPs again.
   - Check the `dig/nslookup` script.
   - Run checks on subdomains.
   - Check the `dig/nslookup` script again.
   - Scan IPs.
   - Scan FQDNs to account for load balancing.

## 3. **Hostne and Inventory Management**
   - Get a list of hostnes and scan them.
   - Create an inventory list of ASNs, subdomains, hostnes, Kubernetes-related info, and web pages. amass

## 4. **Web Application Testing**
   - Use Eyewitness on ports 80 and 443.
   - Fuzz web directories except those returning 401.
   - Review the first page of Eyewitness results.
   - Mark and check all `phpinfo.php` and `iisstart.htm` pages.
   - Check default web pages.
   - Ensure directory indexing does not expose sensitive files.
   - Admin panels should be restricted to specific IP addresses.
   - For login pages, try default credentials.
   - Review responses for user information instead of generic messages.

## 5. **File and FTP Testing**
   - File upload pages should be blocked; try uploading files.
   - For FTP, try default credentials; if connection is possible, mark if SFTP is not used.

## 6. **API Testing**
   - Look for Swagger, WSDL, and any documentation from the site.
   - Give a handful of API shots; if blocked by auth or 401, move on.

## General Testing Approach

## 1. **Hostne and Domain Verification**
   - Perform quick hostne lookup and use Eyewitness.
   - If port 443 is open, check the certificate to see if it provides a domain, then browse by domain.
   - Use Burp Suite on the site and check `robots.txt`.
   - Focus more on active testing on the host side rather than passive or domain-based testing.
   - Pay attention to VPN devices, VoIPs, vendor apps, and cloud VMs.
   - Consider what a ransomware attack would find.
   - Focus on CVEs relevant to the target.
   - Assess the overall attack surface, not just individual links.

## 2. **Quick Testing Guidelines**
   - Don’t spend more than an hour on a single box.
   - If port 443 is open, check with Burp Suite.
   - If SSH is open, test it.
   - For Telnet, check the banner.
   - Use directory fuzzing and content discovery with Burp Suite if worth it.
   - Move quickly and efficiently.