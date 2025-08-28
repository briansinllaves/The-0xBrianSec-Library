# Managing Containerized Apps

## Azure Container Registry (ACR)

### Overview

Azure Container Registry is a managed, private Docker registry service based on the open-source Docker Registry 2.0.

**Key Features:**
- Private container image storage
- Geo-replication for global availability
- Integration with Azure services
- Role-based access control (RBAC)
- Vulnerability scanning with Security Center integration

### Creating an Azure Container Registry

**Navigation:** `Create Resource → Containers → Container Registry`

**Configuration Options:**
- **Registry name** - Must be globally unique
- **Resource group** - Organizational container
- **Location** - Choose region closest to workloads
- **SKU options:**
  - **Basic** - Cost-optimized, lower throughput
  - **Standard** - Balanced performance and cost
  - **Premium** - Highest performance, geo-replication, content trust

### Managing Container Images

**Push Image to Registry:**
```bash
# Login to ACR
az acr login --name myregistry

# Tag image for ACR
docker tag myapp:latest myregistry.azurecr.io/myapp:v1

# Push image
docker push myregistry.azurecr.io/myapp:v1
```

**Pull Image from Registry:**
```bash
# Pull image
docker pull myregistry.azurecr.io/myapp:v1
```

### Access Control

**Authentication Methods:**
- Azure AD individual identity
- Service principal
- Admin account (not recommended for production)
- Repository-scoped access tokens

**RBAC Roles:**
- **AcrPull** - Pull images only
- **AcrPush** - Pull and push images
- **AcrDelete** - Pull, push, and delete images
- **Owner** - Full access including RBAC management

---

## Azure Container Instances (ACI)

### Overview

Azure Container Instances provides fast and simple container deployment without managing virtual machines.

**Use Cases:**
- Simple applications and task automation
- Build and test environments
- Event-driven applications
- Quick container deployments

### Creating Container Instances

**Portal Method:**
`Create Resource → Containers → Container Instances`

**Required Configuration:**
- **Container image** - From ACR, Docker Hub, or other registry
- **OS type** - Linux or Windows
- **Size** - CPU cores and memory allocation
- **Networking** - Public IP, ports, DNS name label

**Advanced Options:**
- **Restart policy** - Always, Never, OnFailure
- **Environment variables** - Configuration settings
- **Command override** - Custom startup commands

### ACI with Azure Container Registry

**Using Managed Identity:**
```bash
# Create ACI with managed identity for ACR access
az container create \
    --resource-group myResourceGroup \
    --name mycontainer \
    --image myregistry.azurecr.io/myapp:latest \
    --assign-identity \
    --acr-identity [system]
```

### Monitoring and Logging

**Container Logs:**
```bash
# View container logs
az container logs --resource-group myResourceGroup --name mycontainer

# Stream logs in real-time
az container logs --resource-group myResourceGroup --name mycontainer --follow
```

**Integration with Azure Monitor:**
- Container insights for monitoring
- Log Analytics workspace integration
- Custom metrics and alerts

---

## Azure Kubernetes Service (AKS)

### Overview

Managed Kubernetes service that simplifies deployment, management, and operations of Kubernetes clusters.

**Key Features:**
- Managed control plane (free)
- Automated upgrades and patching
- Integrated security and monitoring
- Horizontal auto-scaling
- Virtual network integration

### AKS Cluster Creation

**Basic Configuration:**
- **Cluster name** - Unique within resource group
- **Kubernetes version** - Choose supported version
- **Node size** - VM size for worker nodes
- **Node count** - Initial number of nodes

**Authentication and Authorization:**
- **Service principal** - For Azure resource access
- **Managed identity** - Recommended over service principal
- **RBAC** - Enable Kubernetes role-based access control
- **Azure AD integration** - For user authentication

### AKS Security Features

**Network Security:**
- **Network policies** - Control pod-to-pod communication
- **Private clusters** - API server accessible only from private network
- **Authorized IP ranges** - Restrict API server access to specific IPs

**Pod Security:**
- **Pod security policies** - Control pod security contexts
- **Azure Policy for AKS** - Governance and compliance
- **Admission controllers** - Validate and mutate requests

### AKS with Azure Container Registry

**Integration Setup:**
```bash
# Attach ACR to AKS cluster
az aks update -n myAKSCluster -g myResourceGroup --attach-acr myACR
```

**Benefits of Integration:**
- Simplified authentication
- Automatic image pull secrets
- No manual credential management

---

## Container Security

### Image Security

**Base Image Security:**
- Use official, minimal base images
- Regularly update base images
- Scan for vulnerabilities using Azure Security Center
- Implement multi-stage builds to reduce attack surface

**Image Scanning:**
```bash
# Enable vulnerability scanning in ACR
az acr config content-trust update --registry myregistry --status enabled
```

**Content Trust:**
- Digital signature verification
- Ensure image integrity and publisher authenticity
- Available in ACR Premium tier

### Runtime Security

**Secrets Management:**
- Use Azure Key Vault for secrets
- Avoid hardcoded secrets in images
- Implement secret rotation policies

**Network Security:**
- Implement network segmentation
- Use service meshes for secure communication
- Configure ingress controllers with TLS

### Compliance and Monitoring

**Azure Policy Integration:**
- Enforce security policies across containers
- Require approved base images
- Mandate vulnerability scanning

**Monitoring:**
- Azure Monitor for containers
- Security Center recommendations
- Log analytics for audit trails

---

## Container Networking

### ACI Networking

**Public IP Configuration:**
- Automatic public IP assignment
- Custom DNS name labels
- Port configuration for exposed services

**Virtual Network Integration:**
```bash
# Deploy ACI to VNet
az container create \
    --resource-group myResourceGroup \
    --name mycontainer \
    --image nginx \
    --vnet myVNet \
    --subnet mySubnet
```

### AKS Networking

**Network Models:**
- **Basic networking** - Uses kubenet plugin
- **Advanced networking** - Uses Azure CNI plugin
- **Private networking** - Private API server endpoint

**Service Types:**
- **ClusterIP** - Internal cluster communication
- **NodePort** - Expose service on node port
- **LoadBalancer** - Azure Load Balancer integration
- **ExternalName** - DNS CNAME mapping

---

## Container Deployment Patterns

### Blue-Green Deployments

**Implementation Strategy:**
- Maintain two identical production environments
- Route traffic between blue and green environments
- Instant rollback capability
- Zero-downtime deployments

### Rolling Updates

**Kubernetes Rolling Updates:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
```

### Canary Deployments

**Gradual Rollout Strategy:**
- Deploy new version to subset of users
- Monitor metrics and health
- Gradually increase traffic to new version
- Full rollback if issues detected

---

## Container Management with CLI and PowerShell

### Azure CLI Commands

**ACR Management:**
```bash
# List registries
az acr list --output table

# Show registry details
az acr show --name myregistry --resource-group myResourceGroup

# List repositories
az acr repository list --name myregistry

# Delete image
az acr repository delete --name myregistry --image myapp:v1
```

**ACI Management:**
```bash
# List container groups
az container list --output table

# Show container details
az container show --resource-group myResourceGroup --name mycontainer

# Restart container
az container restart --resource-group myResourceGroup --name mycontainer

# Delete container
az container delete --resource-group myResourceGroup --name mycontainer
```

**AKS Management:**
```bash
# List AKS clusters
az aks list --output table

# Get cluster credentials
az aks get-credentials --resource-group myResourceGroup --name myAKSCluster

# Scale cluster
az aks scale --resource-group myResourceGroup --name myAKSCluster --node-count 5

# Upgrade cluster
az aks upgrade --resource-group myResourceGroup --name myAKSCluster --kubernetes-version 1.24.0
```

### PowerShell Commands

**Container Registry:**
```powershell
# Get ACR details
Get-AzContainerRegistry -ResourceGroupName "myResourceGroup"

# Get registry credentials
Get-AzContainerRegistryCredential -ResourceGroupName "myResourceGroup" -Name "myregistry"
```

**Container Instances:**
```powershell
# Get container group
Get-AzContainerGroup -ResourceGroupName "myResourceGroup" -Name "mycontainer"

# Create container group
New-AzContainerGroup -ResourceGroupName "myResourceGroup" -Name "mycontainer" -Image "nginx" -OsType Linux
```

---

## AZ-500 Practice Questions & Answers

### Question Set 1: Container Registry

**Q1: Which ACR SKU supports geo-replication?**
- ❌ Basic
- ❌ Standard
- ✅ **Premium**
- ❌ All SKUs support geo-replication

**Q2: What is the recommended authentication method for production ACR access?**
- ❌ Admin account
- ✅ **Service principal**
- ❌ Anonymous access
- ❌ Shared access keys

### Question Set 2: Container Security

**Q3: Which Azure service provides vulnerability scanning for container images?**
- ❌ Azure Monitor
- ✅ **Azure Security Center**
- ❌ Azure Policy
- ❌ Azure Advisor

**Q4: What is required to enable content trust in Azure Container Registry?**
- ❌ Basic SKU
- ❌ Standard SKU
- ✅ **Premium SKU**
- ❌ Content trust is enabled by default

### Question Set 3: AKS Security

**Q5: Which AKS feature restricts API server access to specific IP addresses?**
- ❌ Network policies
- ❌ Private clusters
- ✅ **Authorized IP ranges**
- ❌ Azure Firewall integration

**Q6: What is the recommended identity type for new AKS clusters?**
- ❌ Service principal
- ✅ **Managed identity**
- ❌ User-assigned identity
- ❌ No identity required

### Question Set 4: Container Instances

**Q7: Which restart policy should be used for batch processing containers?**
- ❌ Always
- ✅ **OnFailure**
- ❌ Never
- ❌ Manual

**Q8: How can ACI access images from a private ACR without credentials?**
- ❌ Anonymous access
- ❌ Service principal
- ✅ **Managed identity**
- ❌ Admin account

### Question Set 5: Networking

**Q9: Which AKS networking option provides better performance and features?**
- ❌ Basic networking (kubenet)
- ✅ **Advanced networking (Azure CNI)**
- ❌ Both are equivalent
- ❌ Performance depends on workload

**Q10: Which Kubernetes service type integrates with Azure Load Balancer?**
- ❌ ClusterIP
- ❌ NodePort
- ✅ **LoadBalancer**
- ❌ ExternalName

### Question Set 6: Container Management

**Q11: Which command attaches an existing ACR to an AKS cluster?**
- ❌ `az aks create --attach-acr`
- ✅ **`az aks update --attach-acr`**
- ❌ `az acr attach --cluster`
- ❌ `kubectl create secret`

**Q12: What happens to containers in ACI when the container group is deleted?**
- ❌ Containers continue running
- ❌ Containers are stopped but preserved
- ✅ **Containers are permanently deleted**
- ❌ Containers are migrated to another group

---

## Key Takeaways for AZ-500

### Critical Concepts

**Container Registry Security:**
- Use Premium SKU for production workloads requiring geo-replication and content trust
- Implement RBAC with least privilege access
- Enable vulnerability scanning and content trust
- Regularly update base images and scan for vulnerabilities

**AKS Security:**
- Use managed identity over service principal for cluster authentication
- Implement network policies for micro-segmentation
- Enable Azure AD integration for user authentication
- Use authorized IP ranges or private clusters for API server protection

**Container Instance Security:**
- Use managed identity for ACR integration
- Deploy to virtual networks for network isolation
- Implement proper restart policies based on workload type
- Monitor container logs and metrics

**Best Practices:**
- Never use admin accounts for production ACR access
- Implement multi-stage Docker builds to reduce image size
- Use Azure Key Vault for secrets management
- Enable monitoring and logging for all container workloads
- Regularly update Kubernetes versions and node images

**CLI/PowerShell Commands:**
- `az acr login` for registry authentication
- `az aks get-credentials` for kubectl configuration
- `az container logs` for troubleshooting
- Monitor costs and resource usage across container services