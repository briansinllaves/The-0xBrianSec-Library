## Nmap Scanning

### Scanning with Nmap

```
nmap -n -T4 -p 443,2379,6666,4194,6443,8443,8080,10250,10255,10256,9099,6782-6784,30000-32767,44134 <pod_ipaddress>/16

```

## NodePort Scanning

### Scanning NodePort Range

When a service is exposed via a NodePort, the port is opened on all nodes, proxying traffic to the declared service. NodePorts typically fall within the range 30000-32767.
```
sudo nmap -sS -p 30000-32767 <IP>
```

### Explanation
- **-p 30000-32767**: Scans the NodePort range.

# Common Container Endpoints to Scan for in Burp Suite

When performing security assessments on containerized applications using Burp Suite, it is essential to target specific endpoints commonly found in containerized environments. Below is a list of common endpoints to include in your scans:

- **Look for API directories**:
  - Inspect `href` values in API responses to discover hidden API directories and endpoints.

```
ffuf -u http://192.168.1.100:8080/FUZZ -w /home/user/wordlists/custom_wordlist.txt`

```

- **Specify HTTP Method**:
    
```
ffuf -u http://192.168.1.100:8080/FUZZ -w /home/user/wordlists/custom_wordlist.txt -X POST
```
    
- **Add Headers**:
```
ffuf -u http://192.168.1.100:8080/FUZZ -w /home/user/wordlists/custom_wordlist.txt -H "Authorization: Bearer <token>"
```

- **Save Output**:    
```
ffuf -u http://192.168.1.100:8080/FUZZ -w /home/user/wordlists/custom_wordlist.txt -o results.json -of json
```
