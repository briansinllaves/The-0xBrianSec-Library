### Converting Text Files and Using Nmap for Scanning

#### Converting Text Files

1. **Ensure Proper File Format**:
   - If you copy-paste or upload a file via `scp`, you may encounter issues with extraneous characters that do not translate properly. To fix these, use the `dos2unix` command.
   - **Example Command**:
     ```bash
     dos2unix ftps.txt
     ```
   - **Explanation**:
     - `dos2unix`: Converts text files with DOS or Mac line endings to Unix line endings.
     - `ftps.txt`: The file you want to convert.

   - **Why Not Use `iconv`**:
     - Using `iconv` for conversion can sometimes cause issues if the characters are not fully in UTF-16. `dos2unix` fixes and removes bad characters instead of translating them incorrectly.

   - **Manual Inspection**:
     - Always do a manual inspection in a console text editor to ensure nothing was missed after conversion.

#### Using the Nmap Parser

- **Nmap Scan to CSV**:
  - Utilize the Nmap XML parser to convert Nmap scan results to CSV format for easier analysis.
  - **Example Command**:
    ```bash
    python nmap_xml_parser.py -f nmap_scan.xml -csv output.csv
    ```
  - **Explanation**:
    - `nmap_xml_parser.py`: Python script to parse Nmap XML results.
    - `-f nmap_scan.xml`: Specifies the Nmap XML file.
    - `-csv output.csv`: Specifies the output CSV file.

- **Filtering Results**:
  - If you see `x20` (space) in the output, look for firewall nes and filter out blank entries under the product field.

#### Nmap Scanning

1. **Basic Nmap Scan**:
   - **Command**:
     ```bash
     sudo nmap -iL /home/brian/targets/global/scopes/belarusscope.txt -p 7,9,13,21,22,23,25,26,37,53,79,80,81,82,88,106,110,111,113,119,123,135,139,143,144,179,199,389,427,443,444,445,446,465,500,513,514,515,543,544,548,554,587,631,636,646,873,990,993,995,1010,1025,1026,1027,1028,1029,1110,1433,1515,1720,1723,1755,1900,2000,2001,2020,2049,2121,2525,2717,3000,3128,3200,3306,3389,3390,3986,4001,4353,4899,4950,4987,5000,5009,5050,5051,5060,5061,5101,5190,5353,5357,5432,5556,5631,5666,5800,5900,5986,6000,6001,6443,6514,6646,7001,7002,7070,8000,8001,8004,8008,8009,8080,8081,8082,8083,8088,8089,8090,8443,8444,8445,8888,9000,9009,9043,9090,9100,9200,9999,10000,10001,10002,12345,20000,32768,49152,49153,49154,49155,49156,49157,50001 --open -sV -n -Pn -vv -oA /home/brian/scans/global/belarus/BY-web-ports
     ```
   - **Explanation**:
     - `-iL /home/brian/targets/global/scopes/belarusscope.txt`: Input file with a list of targets.
     - `-p <ports>`: Specifies the ports to scan.
     - `--open`: Shows only open ports.
     - `-sV`: Version detection.
     - `-n`: No DNS resolution.
     - `-Pn`: No ping (treats all hosts as up).
     - `-vv`: Verbose output.
     - `-oA /home/brian/scans/global/belarus/BY-web-ports`: Output in all formats (normal, XML, and grepable).

2. **Nmap Scan with SQL**:
   - **Command**:
     ```bash
     nmap -vv -n -Pn -sV -p443,1433,1434,1443,5002,5022,5024,5026,16000,16001,16002,16666,16012,16016,16018,16020,16021,16048 ip --open
     $ips | %{ Get-SQLConnectionTest -Instance $_ -Verbose  }
     ```
   - **Explanation**:
     - `-p <ports>`: Specifies the ports to scan.
     - `ip`: Target IP address.
     - `Get-SQLConnectionTest -Instance $_ -Verbose`: Tests SQL connections for the listed instances.

3. **Top Ports Scan**:
   - **Command**:
     ```bash
     nmap -vv -n -Pn -sT --top-ports 2000 --open -iL zero_hosts --resolve-all -oA nmap_scans/_hosts_2000
     ```
   - **Explanation**:
     - `--top-ports 2000`: Scans the top 2000 ports.
     - `-iL lollipop_hosts`: Input file with a list of targets.
     - `--resolve-all`: Resolves all hosts.
     - `-oA nmap_scans/runz_hosts_2000`: Output in all formats (normal, XML, and grepable).

4. **Targeted Nmap Scan**:
   - **Command**:
     ```bash
     nmap -vv -sT -sV -Pn -T4 ip --top-ports 1000 --open -oA stuff-ip
     ```
   - **Explanation**:
     - `5: Target IP address.
     - `-sT`: TCP connect scan.
     - `-sV`: Version detection.
     - `-T4`: Aggressive timing template.
     - `--top-ports 1000`: Scans the top 1000 ports.
     - `-oA data-ip`: Output in all formats (normal, XML, and grepable).

