Nmap Port Scanning

(can only do full connect scan -sT)

Setup ssh: 
```
ssh -D 1337 <userne@ssh_host>
```
```
nmap -oN <output_file.txt> --exclude 127.0.0.1 --top-ports 1800 -T4 -vvv --max-rtt-timeout 500ms --max-retries 3 --host-timeout 30m --max-scan-delay 500ms -Pn -sT --version-intensity 1 --open --proxies socks4://127.0.0.1:1337 -iL <IP_List.txt>
```
