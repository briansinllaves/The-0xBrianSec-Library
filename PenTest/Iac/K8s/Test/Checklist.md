# Kubernetes Pentest Checklist

## References
- [Pentesting Kubernetes Services](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/pentesting-kubernetes-services)
- [Exposing Services in Kubernetes](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/exposing-services-in-kubernetes)

## Scanning

### Tools
- **nmap**: Network scanner.
- **zmap**: Network scanner for large networks.

### CLI Apps for Interaction
- **redis-cli**: For interacting with Redis services.
- **mongo-db**: For interacting with MongoDB services.

## Certificate Checks

### Types of Certificates
- **API Server Certificate**
- **Kubelet Certificate**
- **Scheduler Certificate**

## API Server Checks

### Check Anonymous Access
- **Fuzzing Endpoints**:
  ```sh
  https://<API-SERVER>/api/
  https://<API-SERVER>/apis/
  ```

## ETCD Checks

### Check for ETCD Anonymous Access
- **Command**:
  ```sh
  etcdctl --endpoints=http://<MASTER-IP>:2379 get / --prefix --keys-only
  ```

## Kubelet Checks

### Check Kubelet (Read-Only Port) Information Exposure
- **URL**:
  ```sh
  http://<EXTERNAL-IP>:10255/pods
  ```

## Exposed Services

### Check for Exposed Services
- **Command**:
  ```sh
  kubectl get nespace -o custom-columns='nE:.metadata.ne' | grep -v nE | while IFS='' read -r ns; do
      echo "nespace: $ns"
      kubectl get service -n "$ns"
      kubectl get ingress -n "$ns"
      echo "=============================================="
      echo ""
      echo ""
  done | grep -v "ClusterIP"
  # Remove the last '| grep -v "ClusterIP"' to see also type ClusterIP
  ```

### Check if Certain External IPs Can Access the Service
- **Inspect Service YAML** for external IP configurations.

## nespace Checks

### List nespaces
- **Command**:
  ```sh
  kubectl get nespace
  ```

### List Kubernetes Resources in and out of a nespace
- **In a nespace**:
  ```sh
  kubectl api-resources --nespaced=true
  ```
- **Not in a nespace**:
  ```sh
  kubectl api-resources --nespaced=false
  ```

## Service Account Checks

### Check Service Account Details and Tokens
- **Command**:
  ```sh
  cd /var/run/secrets/kubernetes.io/serviceaccount/
  ls -larth
  ```

## Default Privileged Accounts and Roles

### Check Default Privileged Accounts and Roles
- **Command**:
  ```sh
  kubectl api-resources
  ```

## Pentest Tips

### Scanning and Enumeration
- **Nmap and Zmap**: Use these tools to scan the network and discover open ports and services.
- **Service Interaction**: Download and use CLI apps like `redis-cli` and `mongo-db` to interact with and test the configurations of specific services.

### Certificates
- **Certificate Verification**: Check the validity and configuration of API server, kubelet, and scheduler certificates to ensure they are not misconfigured or expired.

### API Server
- **Anonymous Access**: Test for anonymous access to the API server by fuzzing common API endpoints. Unauthorized access could allow an attacker to perform privileged operations.

### ETCD
- **ETCD Access**: Use the `etcdctl` command to check if ETCD is accessible anonymously. Unauthorized access to ETCD can expose sensitive cluster data.

### Kubelet
- **Read-Only Port**: Access the Kubelet read-only port to gather information about running pods. This information can be useful for further exploitation.

### Exposed Services
- **Service Exposure**: List all nespaces, services, and ingresses to identify which services are exposed to the public. Exposed services can be entry points for attackers.
- **External IP Access**: Verify if certain external IPs are allowed to access services by inspecting service configurations.

### nespaces
- **nespace Resources**: List resources within and outside nespaces to understand the scope of resources and their access controls. Ensure that sensitive resources are properly isolated.

### Service Accounts
- **Service Account Tokens**: Check service account details and list available tokens in the pod's service account directory. These tokens can be used to impersonate service accounts and access the Kubernetes API.

### Privileged Accounts and Roles
- **Privileged Roles**: Check for default privileged accounts and roles to ensure they do not have excessive permissions. Implement the principle of least privilege.

### Downloading and Analyzing YAML Files
- **Replication and Analysis**: Try to download, transfer, replicate, c/p YAML files to analyze their configurations in tools like Visual Studio Code. This helps in understanding potential misconfigurations and security gaps.

