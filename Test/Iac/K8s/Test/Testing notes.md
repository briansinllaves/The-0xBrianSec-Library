# Kubernetes Security Notes

## Reference
For detailed guidance on Kubernetes security, visit: [HackTricks - Pentesting Kubernetes Security](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security)
## API Directory Enumeration

- **Look for API directories**:
- Inspect `href` values in API responses to discover hidden API directories and endpoints.

## Network Spoofing

### ARP Spoofing
- **By Default**: Techniques like ARP spoofing and DNS spoofing are possible within the Kubernetes network.
- **NET_RAW Capability**:
  - Inside a pod with the `NET_RAW` capability (enabled by default), you can send custom-crafted network packets.
  - This allows performing Man-in-the-Middle (MitM) attacks via ARP spoofing against other pods on the same node.

### DNS Spoofing
- **Node Co-location**:
  - If a malicious pod is on the same node as the DNS server, you can perform DNS spoofing attacks.
  - This affects all pods in the cluster, redirecting their DNS queries to malicious addresses.

### Mitigation Tips
- **Restrict Capabilities**:
  - Limit the `NET_RAW` capability for pods to prevent them from sending custom network packets.
- **Network Policies**:
  - Implement strict network policies to control traffic flow and reduce the risk of MitM attacks.
- **Node Isolation**:
  - Ensure critical services like DNS servers are isolated and not running on the same nodes as potentially untrusted pods.
- **Monitoring**:
  - Continuously monitor network traffic for suspicious activities indicative of ARP or DNS spoofing.

By understanding and mitigating these network spoofing risks, you can enhance the security of your Kubernetes environment.