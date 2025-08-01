## Objective
Exploit Server-Side Request Forgery (SSRF) vulnerabilities to access internal services and metadata within Kubernetes.

## Steps

### 1. Exploit SSRF to Access Metadata API
Use the SSRF vulnerability to query the Kubernetes metadata API:

```sh
curl http://metadata-db/latest/
```

### 2. Query Current Container/Pod for Running Services
Scan different ports and addresses within the container/pod to identify running services:

```sh
nmap -sT -p- localhost
```

- **`-sT`**: TCP connect scan
- **`-p-`**: Scan all ports

### 3. Query Internal Kubernetes Services
Attempt to access other services running within the cluster by querying known service ports and addresses. For example, try common service ports like 80, 443, 2379 (etcd), 6443 (Kubernetes API), etc.

#### Example: Querying Kubernetes API
If you suspect a Kubernetes API server might be accessible, use:

```sh
curl -k https://<internal-service-ip>:6443/api
```

### 4. Automate Scanning for Open Ports and Services
Automate the process of querying internal services using a tool like `ffuf` or a custom script.

#### Example with `ffuf`
```sh
ffuf -u http://<internal-service-ip>:FUZZ -w /path/to/SecLists/Discovery/Web-Content/raft-large-directories.txt
```

### Mitigation Tips
- **Network Policies**: Implement network policies to restrict pod-to-pod communication and limit access to sensitive internal services.
- **Metadata API Protection**: Restrict access to the metadata API from within containers and only allow necessary services to query it.
- **Service Whitelisting**: Use whitelisting to limit which internal services can be accessed by specific pods or containers.
- **Regular Security Audits**: Conduct regular security audits and penetration testing to identify and mitigate SSRF vulnerabilities.
