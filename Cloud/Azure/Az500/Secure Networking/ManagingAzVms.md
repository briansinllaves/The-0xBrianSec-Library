# Managing Azure VMs

## Linux SSH Public Key Authentication

### Overview

SSH public key authentication provides secure, password-less access to Linux VMs using cryptographic key pairs.

**Key Components:**
- **Public key** - Stored on the VM (server side)
- **Private key** - Stored on client/admin workstation
- **Authentication process** - Private key proves identity to public key

### SSH Key Creation Options

**During VM Creation:**
- Generate key pair automatically during VM deployment
- Upload existing public key during VM creation process

**Post-Deployment:**
- VM Overview → Reset Password → Configure SSH keys
- Generate new key pairs using SSH tools

---

## Generating SSH Key Pairs

### Key Generation Tools

**PuTTY Key Generator:**
- Use PuTTYgen for Windows environments
- Generates key pairs in PuTTY format (.ppk)
- Can convert between different key formats

**OpenSSH (Linux/macOS/Windows):**
```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -C "admin@contoso"
```

### Key Storage Locations

**Public Key Storage:**
- **On VM:** `~/.ssh/authorized_keys` file
- **Azure Portal:** VM Overview → SSH Keys section

**Private Key Storage:**
- **Client workstation:** `~/.ssh/id_rsa` (OpenSSH format)
- **PuTTY:** Convert to `.ppk` format for PuTTY SSH client
- **Authentication:** SSH client → Private key → Proves identity to VM

### PuTTY Configuration

**Private Key Format Conversion:**
- **Requirement:** PuTTY requires `.ppk` format
- **Process:** Use PuTTYgen to convert OpenSSH keys
- **Configuration:** SSH → Auth → Browse to `.ppk` file

---

## Configuring Linux SSH Public Key Authentication

### File System Storage

**SSH Directory Structure:**
- **Location:** `~/.ssh/` directory on Linux VM
- **Public Key File:** `~/.ssh/authorized_keys`
- **File Permissions:** Proper permissions critical for security

**Key Management:**
- Multiple public keys can be stored in `authorized_keys`
- Each key typically on separate line
- Comments help identify key owners

---

## Managing VMs Through Azure Bastion

### Overview

Azure Bastion enables secure RDP and SSH access to VMs without public IP addresses.

**Key Benefits:**
- **No public IP required** on target VMs
- **Browser-based access** directly from Azure Portal
- **No additional client software** needed
- **Secure access** without exposing RDP/SSH ports to internet

### Bastion Requirements

**Network Requirements:**
- **AzureBastionSubnet** - Dedicated subnet (/26 or larger)
- **Standard SKU public IP** for Bastion host
- **VNet integration** - Must be in same VNet as target VMs

### Connection Process

**Windows VM Access:**
1. **Navigate to VM** → Overview
2. **Click Connect** → Choose Bastion
3. **Authentication options:**
   - Username and password
   - Key Vault stored credentials
   - Azure AD authentication

**Connection Details:**
- **Protocol:** RDP for Windows, SSH for Linux
- **Browser-based:** No external RDP/SSH client needed
- **Secure tunnel:** Traffic encrypted through Azure backbone

---

## Enabling JIT VM Access

### Overview

Just-In-Time (JIT) VM Access provides time-limited, source IP-restricted access to VM management ports.

**Security Benefits:**
- **Temporary access** - Specific time duration
- **Source IP restriction** - Limit access to specific locations
- **Automatic cleanup** - Access automatically revoked after time expires

### JIT Configuration

**Enable JIT:**
1. **Navigate to target VM** → Configuration
2. **Click "Enable JIT"** button
3. **Configure access policies** for different ports

**Microsoft Defender for Cloud Integration:**
1. **Defender for Cloud** → Workload Protections → Servers
2. **Advanced Protection** → JIT
3. **Review configured and not configured** VMs

### JIT Access Request Process

**Request Access:**
1. **Click target server** in JIT dashboard
2. **Choose "Request Access"**
3. **Configure request parameters:**
   - **Toggle ports** - Enable specific ports (RDP 3389, SSH 22)
   - **Source IP** - "My IP" or custom range
   - **Time duration** - Up to maximum allowed (default 3 hours)
   - **Justification** - Reason for access request

**Automatic NSG Modification:**
- JIT dynamically modifies NSG rules
- Allows specified port for specified time
- Automatically removes rules when time expires

---

## Adding Azure VM Extensions

### Overview

VM Extensions are lightweight software agents that provide additional functionality to Azure VMs.

**Navigation:** Virtual Machine → Settings → Extensions + Applications

### Extension Management

**Review Extension Status:**
- **View installed extensions** and their status
- **Click extension link** for detailed information
- **Install/Uninstall** extensions from overview

**Common Extension Types:**
- **Custom Script Extension** - Execute scripts on VM
- **Diagnostic Extension** - Monitoring and logging
- **Dependency Agent** - Service mapping and monitoring
- **Azure Monitor Agent** - Centralized monitoring

### Custom Script Extension Configuration

**Use Cases:**
- **Post-deployment configuration** of VM settings
- **Software installation** and configuration
- **Application deployment** automation

**Configuration Process:**
1. **Click Install** → Choose "Custom Script Extension"
2. **Script Source Options:**
   - **Upload script file**
   - **Browse Storage Account** for existing scripts
3. **Command Configuration:**
   - **Command:** `sh who.sh` (example for Linux)
   - **Create/Deploy** extension

### Custom Script Extension Limitations

**Important Constraints:**
- **Script must not require user input** - Fully automated execution
- **No reboot statements** - Cannot restart VM during execution
- **98-minute execution limit** - Maximum runtime constraint
- **Single execution** - Can only be executed once per deployment

### VM Managed Identity for Extensions

**System-Assigned Identity:**
1. **VM → Identity** → Enable "System Assigned"
2. **Purpose:** Allows VM to authenticate to other Azure services
3. **Permission Assignment:** Grant permissions to access required resources

**Storage Account Access Example:**
1. **Storage Account → IAM** → Role Assignments
2. **Assign "Storage Blob Data Reader"** to VM's managed identity
3. **VM can now access** Storage Account → Container → Scripts → who.sh

---

## Limiting VM Access Using Roles

### RBAC Scope Options

**Resource-Level Assignment:**
- **VM Overview → IAM** → Add Role Assignments
- **Granular control** over individual VMs
- **Highest administrative overhead**

**Resource Group-Level Assignment:**
- **Resource Group → IAM** → Add Role
- **VM permissions apply** to entire resource group
- **Balanced approach** - good control with manageable overhead

**Subscription-Level Assignment:**
- **Subscription Overview → IAM** → Add Role
- **Permissions trickle down** to all resources
- **Broadest scope** - use carefully

### Common VM Roles

**Virtual Machine Contributor:**
- **Manage VMs** but not access data
- **Cannot manage** networking or storage independently
- **Suitable for** VM administrators

**Virtual Machine User Login:**
- **Login to VM** using Azure AD credentials
- **No administrative access** to VM
- **Suitable for** end users needing VM access

### Role Assignment Process

**Search and Assign:**
1. **Search "Virtual Machine"** roles
2. **Select Virtual Machine Contributor**
3. **Assign to:**
   - **Users** - Individual user accounts
   - **Groups** - User groups for easier management
   - **Managed Identity** - For service-to-service communication

### Managed Identity Lifecycle

**System-Assigned Identity:**
- **Tied to VM lifecycle** - Deleted when VM is deleted
- **Automatic cleanup** - No orphaned identities
- **Must manually clean up** role assignments if VM deleted

**User-Assigned Identity:**
- **Independent lifecycle** - Not tied to specific resource
- **Can be shared** across multiple resources
- **Persists after** resource deletion
- **More complex management** but greater flexibility

---

## AZ-500 Practice Questions & Answers

### Question Set 1: VM Extensions

**Q1: What is the purpose of a Microsoft Azure virtual machine extension?**
- ❌ To provide the VM with access to a key vault
- ✅ **To enable a small software agent in the VM to provide additional functionality**
- ❌ To allow VM management through Azure Bastion
- ❌ To allow VM just-in-time (JIT) access

### Question Set 2: RBAC Strategy

**Q2: What strategy allows management of some, but not all, VMs with the least administrative effort?**
- ✅ **Apply RBAC roles to a resource group**
- ❌ Apply RBAC roles to a management group
- ❌ Apply RBAC roles to individual VMs
- ❌ Apply RBAC roles to the entire subscription

### Question Set 3: JIT Access

**Q3: When configuring VM JIT access, what is the default maximum request time?**
- ❌ 1 hour
- ❌ 30 minutes
- ✅ **3 hours**
- ❌ 15 minutes

### Question Set 4: Bastion Benefits

**Q4: What is the benefit of managing Azure VMs through Bastion?**
- ❌ VMs do not need a private IP address
- ❌ Linux VMs do not require extensions
- ❌ Windows VMs do not require extensions
- ✅ **VMs do not need a public IP address**

### Question Set 5: SSH Public Key Storage

**Q5: You configured SSH public key auth for a Linux VM. Where is the public key stored?**
- ❌ On the admin station in ~/.ssh/id_rsa
- ✅ **On the Linux server in ~/.ssh/authorized_keys**
- ❌ On the Linux server in ~/id_rsa
- ❌ On the admin station in ~/.ssh/authorized_keys

### Question Set 6: SSH Private Key Storage

**Q6: On a Linux admin station, where is the private key stored?**
- ❌ ~/.ssh/authorized_keys
- ❌ On the Linux server in ~/id_rsa
- ❌ On the Linux server in ~/.ssh/authorized_keys
- ✅ **~/.ssh/id_rsa**

### Question Set 7: Cryptographic Keys

**Q7: Which type of key is used to decrypt (public-key crypto)?**
- ❌ Public
- ❌ Symmetrical
- ❌ Asymmetrical
- ✅ **Private**

---

## Key Takeaways for AZ-500

### Critical Concepts

**SSH Key Authentication:**
- **Public key** stored in `~/.ssh/authorized_keys` on VM
- **Private key** stays on admin workstation (`~/.ssh/id_rsa`)
- **PuTTY** requires `.ppk` format conversion
- **Security benefit:** Eliminates password-based attacks

**Azure Bastion:**
- **Requires AzureBastionSubnet** (/26 or larger)
- **No public IP needed** on target VMs
- **Browser-based** RDP/SSH access through Azure Portal
- **Eliminates need** for inbound NSG rules on management ports

**Just-In-Time Access:**
- **Managed through** Microsoft Defender for Cloud
- **Dynamically modifies** NSG rules for temporary access
- **Default maximum** commonly 3 hours
- **Source IP restrictions** enhance security

**VM Extensions:**
- **Lightweight agents** providing additional functionality
- **Custom Script Extension** for post-deployment automation
- **Non-interactive execution** - no user input allowed
- **Time-bounded** - 98-minute maximum execution

**RBAC Best Practices:**
- **Assign at narrowest scope** that meets operational requirements
- **Resource group level** often provides best balance of control and effort
- **System-assigned identities** tied to resource lifecycle
- **User-assigned identities** independent of specific resources

**Security Architecture:**
- **Layer defense** using JIT, Bastion, and key-based authentication
- **Minimize attack surface** by eliminating public IPs where possible
- **Automate security** through extensions and managed identities
- **Regular review** of role assignments and access patterns