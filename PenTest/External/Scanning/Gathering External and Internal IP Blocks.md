### Gathering External and Internal IP Blocks of a Company

#### Collecting Information with Amass

1. **Collect Subdomains and WHOIS Data for `ABCD.com`**:
   ```bash
   amass intel -d ABCD.com -whois
   ```

2. **Collect Subdomains and WHOIS Data for `ABCDinternal.com`**:
   ```bash
   amass intel -d ABCDinternal.com -whois
   ```

3. **Collect Information Using Organization ne**:
   ```bash
   amass intel -org pricewaterhousecoopers
   ```

4. **Enumerate Subdomains for Domains Listed in a File**:
   ```bash
   amass enum -active -df domains.txt
   amass enum -active -df amass/domains2.txt
   ```

5. **Gather IP Information for a Specific ASN**:
   ```bash
   amass intel -active -asn 36205
   ```

6. **Gather IP Information for Multiple ASNs**:
   ```bash
   amass intel -active -asn 50061,17906,19623,20426,21296,36205 -ip
   ```

#### Moving from External to Internal

1. **Using IP Blocks with Nmap**:
   - Once you have a block of IPs, use Nmap to scan for open ports and services.
   - Example Nmap Command:
     ```bash
     nmap -sV -p 1-65535 -iL ip_blocks.txt -oN nmap_results.txt
     ```
   - `-sV`: Service version detection
   - `-p 1-65535`: Scan all ports
   - `-iL ip_blocks.txt`: Input file containing the list of IP blocks
   - `-oN nmap_results.txt`: Output file for the scan results

2. **Using Subdomains with EyeWitness**:
   - After collecting a list of subdomains, use EyeWitness to capture screenshots and gather additional information.
   - Example EyeWitness Command:
     ```bash
     python3 EyeWitness.py --web -f subdomains.txt --timeout 10 --no-prompt -d ./eyewitness_results
     ```
   - `--web`: Capture screenshots of web applications
   - `-f subdomains.txt`: Input file containing the list of subdomains
   - `--timeout 10`: Set timeout for each request
   - `--no-prompt`: Run without user interaction
   - `-d ./eyewitness_results`: Output directory for the results

#### Example Workflow

1. **Collect External Information**:
   - Run Amass commands to gather subdomains, WHOIS data, and IP blocks.
   
2. **Move to Internal Information Gathering**:
   - Use Nmap to scan the collected IP blocks for open ports and services.
   - Example Nmap Command:
     ```bash
     nmap -sV -p 1-65535 -iL ip_blocks.txt -oN nmap_results.txt
     ```

3. **Capture Web Application Screenshots**:
   - Use EyeWitness to capture screenshots and gather information about the subdomains.
   - Example EyeWitness Command:
     ```bash
     python3 EyeWitness.py --web -f subdomains.txt --timeout 10 --no-prompt -d ./eyewitness_results
     ```

By following this workflow, you can efficiently gather external and internal information about a company's network and web applications from an external perspective.

# Also use DNS and checkout FQDNs and subdomains