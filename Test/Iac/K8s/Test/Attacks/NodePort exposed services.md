# Pentesting Note: NodePort Exposed Services

## Objective
Identify and exploit services exposed via NodePort in a Kubernetes cluster to uncover unauthenticated and unauthorized services.

## Background
When services are exposed using NodePort in Kubernetes, they become accessible on the nodes' external IP addresses. If these nodes lack firewall/network security, it can lead to potential vulnerabilities.

## Steps

### 1. Identify Kubernetes Nodes External IP Addresses
Retrieve the external IP addresses of Kubernetes nodes:

```sh
kubectl get nodes -o wide
```

### 2. Scan IP Addresses with Nmap
Scan the identified IP addresses for open NodePort ranges (30000-32767):

```sh
nmap -p 30000-32767 <node_external_ip>
```

### Explanation
- **30000-32767**: Default range for NodePorts in Kubernetes.
- **<node_external_ip>**: Replace with the external IP address of the node.

### 3. Verify NodePort Exposure
Once an open NodePort is identified, verify by connecting to it:

#### Using Netcat
Check if the port is open using Netcat:

```sh
nc -zv <node_external_ip> <nodeport>
```

#### Using a Browser
If the service is HTTP-based, you can access it via a web browser:

```sh
http://<node_external_ip>:<nodeport>
```

### Summary of Commands
```sh
# Get external IP addresses of Kubernetes nodes
kubectl get nodes -o wide

# Scan for open NodePorts
nmap -p 30000-32767 <node_external_ip>

# Verify open port using Netcat
nc -zv <node_external_ip> <nodeport>

# Access the service in a web browser (if applicable)
http://<node_external_ip>:<nodeport>
```

### Mitigation Tips
- **Implement Firewalls**: Ensure nodes have firewalls configured to block unauthorized access to NodePorts.
- **Network Policies**: Use Kubernetes Network Policies to restrict traffic to NodePorts.
- **Secure Configuration**: Avoid exposing sensitive services via NodePort; use other methods like Ingress controllers for controlled access.
- **Monitoring**: Continuously monitor NodePort traffic and logs for unauthorized access attempts.
