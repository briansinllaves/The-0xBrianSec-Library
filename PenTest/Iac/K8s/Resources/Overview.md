https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security

https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/kubernetes-basics


A Kubernetes cluster consists of a set of worker machines, called nodes, that run containerized applications. Every cluster has at least one worker node.

Below are very high-level components in Kubernetes Cluster

**Control Plane Components**


# Kubernetes Production Setup on Multiple Nodes

## Control Plane Components

### API Server
- **Role**: Acts as the front-end for the Kubernetes control plane.
- **Function**: Exposes the Kubernetes API for managing and interacting with the cluster.
- **Pentesting Tip**: Check for anonymous access and ensure secure API server configurations.

### etcd
- **Role**: Consistent and highly-available key-value store.
- **Function**: Serves as Kubernetes' backing store for all cluster data.
- **Pentesting Tip**: Verify that etcd access is secure and not exposed to unauthorized users.

### Scheduler
- **Role**: Watches for newly created pods.
- **Function**: Assigns pods to available nodes based on resource requirements and constraints.

### Controller Manager
- **Role**: Runs controller processes.
- **Function**: Ensures the desired state of the cluster matches the actual state.

## Node Components
Run application workloads.

### kubelet
- **Role**: Node agent.
- **Function**: Ensures containers are running in a pod and communicates with the control plane to report the node's status.

### Network Proxy (kube-proxy)
- **Role**: Maintains network rules.
- **Function**: Allows communication between pods across the cluster.

### Container Runtime
- **Role**: Executes containers within pods.
- **Function**: Manages the container lifecycle, isolation, and resource constraints.
- **Example**: Docker, containerd, CRI-O.

## Add-Ons and Services

### DNS
- **Role**: Provides DNS-based service discovery.
- **Function**: Allows pods to communicate with each other by their nes.
- **Pentesting Tip**: Ensure DNS services are secure and not leaking information.

### Container Resource Monitoring
- **Role**: Monitors resource usage.
- **Function**: Collects and exposes metrics about resource usage and performance of containers and pods.
- **Pentesting Tip**: Monitor for unusual resource usage patterns that could indicate security issues.

### Cluster-level Logging
- **Role**: Captures and stores logs.
- **Function**: Aids in troubleshooting and auditing activities within the cluster.
- **Pentesting Tip**: Ensure logs are properly secured and sensitive data is not exposed.

### Services
- **Role**: Facilitates communication between pods.
- **Function**: Provides a static IP with a DNS ne for internal communication.
- **Pentesting Tip**: Verify service configurations to ensure they do not expose unnecessary ports or data.

## Best Practices for Security

1. **API Server Security**: Ensure secure configurations, use RBAC (Role-Based Access Control) to limit access.
2. **etcd Security**: Secure etcd with authentication and encryption, restrict access.
3. **Pod Security**: Use Pod Security Policies (PSPs) or Open Policy Agent (OPA) to enforce security standards.
4. **Network Security**: Implement network policies to control traffic flow between pods and services.
5. **Monitoring and Logging**: Regularly review logs and metrics for suspicious activity.

