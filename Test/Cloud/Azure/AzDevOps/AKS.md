 As a part of the orchestration process, the cluster needs to be assigned an identity (a Service Principal 

https://www.netspi.com/blog/technical/cloud-penetration-testing/extract-credentials-from-azure-kubernetes-service/

### Identity Assignment in Azure Kubernetes Service (AKS)

**Identity Assignment in the Cluster Orchestration Process:**
- **Service Principal (SP)**
  - Existing SP: Can be used to assign an identity to the AKS cluster.
  - Roles: Additional roles may already be assigned to this SP in the Azure tenant.
- **Managed Identity (MI)**
  - System-assigned MI: Automatically created and managed by Azure, but does not have assigned roles in the subscription by default.
  - User-assigned MI: Created in the Resource Group for VMSS (Virtual Machine Scale Sets) cluster resources. Typically used when there is no "Identity" menu in the AKS portal blade.

**Accessing Cluster Credentials:**
- **Service Principal or Managed Identity Credentials:**
  - Execute commands on the cluster to retrieve credentials.
  - Use an authenticated `kubectl` session or execute commands directly on the VMSS instances supporting the cluster.

**Resource Group Creation in AKS:**
- **When a new AKS cluster is created:**
  - A corresponding resource group is automatically created in the subscription.
  - The new resource group is ned based on the original resource group where the AKS resource was created, combined with the cluster ne.

**Client ID, Password, and Tenant ID:**
- These credentials are necessary for accessing and managing the AKS cluster:
  - **Client ID**: Identifies the application or service principal.
  - **Password**: Secret associated with the service principal.
  - **Tenant ID**: Identifies the Azure Active Directory (AAD) tenant.

### Key Points:
- **Service Principals** and **Managed Identities** provide a way for applications to access resources securely.
- **System-assigned Managed Identity** is automatically managed and lifecycle-tied to the resource.
- **User-assigned Managed Identity** is managed by the user and can be shared across multiple resources.
- **Resource Groups** are essential for organizing resources in Azure, and AKS creates a new resource group during the cluster setup.	
	![[Pasted image 20221206171111.png]]

### Accessing Service Principal Credentials in AKS

**Storage of Service Principal Credentials:**
- **Location**: Azure stores the Service Principal credentials in the `/etc/kubernetes/azure.json` file on the cluster.
- **Format**: Credentials are stored in clear text to enable the cluster to utilize them effectively.

**Microsoft Documentation**: Further details on the design choice and implementation can be found in the [Microsoft documentation](https://learn.microsoft.com/en-us/azure/aks/kubernetes-service-principal?tabs=azure-cli).

### Accessing the `azure.json` File

**Steps to Access the File:**
1. **Authenticate and Connect**: Ensure you have an authenticated session with the AKS cluster, typically done using `kubectl`.
2. **Execute Command**: Run a command on the VMSS instance supporting the cluster to access the file.

**Command to Execute:**
```sh
cat /etc/kubernetes/azure.json
```

**Example Process:**
1. **Open a Shell Session on a Node**:
   ```sh
   kubectl get nodes
   kubectl debug node/<node-ne> --image=mcr.microsoft.com/dotnet/runtime-deps:6.0
   ```

2. **Access the VMSS Instance**:
   ```sh
   # Once in the shell session
   chroot /host
   ```

3. **Retrieve and Display the File**:
   ```sh
   cat /etc/kubernetes/azure.json
   ```

**Output**: The command will display the contents of the `azure.json` file, revealing the Service Principal credentials.

### Key Points:
- **Security Implication**: Storing credentials in clear text, while functional, poses security risks. It’s important to control access to nodes and ensure only authorized personnel can execute such commands.
- **Best Practices**: Regularly rotate Service Principal credentials and monitor access logs for any unauthorized access attempts.

Understanding the location and method to access the `azure.json` file is crucial for managing and securing Service Principal credentials in AKS.

	![[Pasted image 20221206171142.png]]
	
	
