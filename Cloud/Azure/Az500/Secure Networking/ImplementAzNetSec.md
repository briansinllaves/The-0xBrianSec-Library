# Implementing Azure Network Security

## Application Security Groups (ASGs)

### Overview

Application Security Groups help group VMs together logically for network security management.

**Key Characteristics:**
- **One per application** - Logical grouping by application role
- **Allows different connectivity rules** for multiple apps/VMs within single subnet
- **Used in NSG rules** as source or destination
- **Scales well** - No need to reference specific IP addresses
- **Resource scope** - Created in subscription within resource group

### How ASGs Work

**NSG Integration:**
- NSG references an ASG instead of IP addresses
- **Example:** SSH rule with source `*`, destination set to specific ASG
- Eliminates need to update rules when VM IP addresses change

**Benefits:**
- Logical application grouping
- Simplified rule management
- Automatic IP address tracking
- Scalable security policy application

---

## Configuring ASGs

### Creating ASG

**Navigation:** Search "Application Security Groups" in Azure portal

**Creation Process:**
1. **Create new** ASG resource
2. **Choose subscription** and resource group
3. **Name** the ASG (e.g., WebServers, DatabaseServers)

### Applying ASGs

**VM Assignment:**
1. **Navigate to VM** → Networking
2. **ASG tab** - Choose appropriate ASG
3. **Associate** VM network interface with ASG

**NSG Rule Configuration:**
1. **Search NSG** in portal
2. **Choose Inbound Security Rules**
3. **Select rule** to modify
4. **Destination** = Application Security Group
5. **Choose specific ASG** from dropdown

---

## Azure Firewall and Firewall Manager

### Azure Firewall Requirements

**Network Prerequisites:**
- **Requires VNet subnet** named "AzureFirewallSubnet"
- **Uses at least one static public IP** address
- **Controls inbound/outbound traffic** through rule processing
- **Rule processing by priority** - lower numbers processed first

### NAT Rules

**SNAT (Source NAT):**
- **Outgoing traffic** assumes firewall IP address
- **Configured by default** for all outbound connections
- Hides internal IP addresses from external networks

**DNAT (Destination NAT):**
- **Inbound traffic** translation from public to private addresses
- **Manual configuration required**
- **Use case:** Expose internal services to internet

**Example DNAT Rule:**
- **Name:** Incoming-priority-100
- **Protocol:** TCP
- **Destination:** AzFirewallPublicIP:80
- **Translation:** InternalServerIP:80

### Rule Types and Processing Order

**Rule Evaluation Priority:**
1. **NAT Rules** - Processed first
2. **Network Rules** - Processed second
3. **Application Rules** - Processed last

**Network Rules:**
- **Applies to outbound traffic**
- **Checked before application rules**
- **No deep inspection** - examines IP, port, protocol only
- Faster processing than application rules

**Application Rules:**
- **All FQDNs blocked by default**
- **Must specify allowed FQDNs**
- **Wildcards supported** (*.domain.com or *)
- **Protocol specification** - HTTP or HTTPS with port
- **Deep packet inspection** - verifies protocol matches port
- **Allow or Deny actions** available

---

## Managing Azure Firewall Application Rules

### Firewall Creation

**Resource Creation Process:**
1. **Resource** → Search "Azure Firewall" → Microsoft Firewall
2. **Choose subscription** and resource group
3. **SKU Selection:**
   - **Standard** - Basic firewall features
   - **Premium** - SSL termination, IDPS capabilities

**Network Configuration:**
- **Address space** - Recommended: 10.0.0.0/16
- **Subnet address** - Example: 10.0.1.0/24
- **Forced tunneling** - Enable if traffic should route through on-premises (site-to-site VPN)

### Application Rule Configuration

**Rule Management:**
1. **Navigate to firewall** → Overview
2. **Copy public IP** for reference
3. **Rules (Classic)** → Application Rules

**Example Application Rule:**
- **Priority:** 100
- **Action:** Allow
- **Source:** * (any)
- **Protocol:** HTTPS:443
- **Target FQDN:** www.skillsoft.com
- **Rule Name:** Skillsoft-Allow

---

## Managing Azure Firewall Network Rules

### Network Rule Processing

**Key Concept:** Network rules are checked and enforced **before** application rules

**Configuration Path:** Resources → Firewall → Rules (Classic) → Network Rules

### DNAT Rule Example

**RDP Server Access:**
- **Name:** RDPServer1
- **Protocol:** TCP
- **Source:** * (any)
- **Destination:** FirewallPublicIP:3389
- **Translated Address:** PrivateVMIP:3389

**Important:** Bastion hosts don't have public IPs. To connect via RDP, use the NATted public IP of firewall mapped to internal private IP of VM.

---

## Managing Azure Firewall NAT Rules

### VNet Peering for Firewall

**Network Architecture:**
- **VNet Peering** - Connect app VNet to firewall VNet
- **Default Deny** - Nothing allowed out by default unless explicitly permitted
- **Rule Configuration** required for any outbound access

**Connection Method:**
Use firewall's public IP with NAT rules to access internal resources, not VM's direct public IP

---

## Configuring Azure Application Gateway

### Overview

Azure Application Gateway functions as a **web load balancer** with Layer 7 capabilities.

### Creation Process

**Resource Creation:**
1. **Resource** → Marketplace → Application Gateway
2. **Tier Selection:** WAF v2 (Web Application Firewall version 2)
3. **Autoscaling Configuration:**
   - **Minimum instances:** 2
   - **Maximum instances:** 4
   - **Availability zones:** Configure as needed
4. **WAF Policy:** Create new (e.g., WAFPolicy1)
5. **VNet Creation:** Create new virtual network if needed

### Backend Configuration

**Backend Pool Setup:**
- **Add backend pool** pointing to:
  - App Services
  - Virtual machines
  - FQDNs
  - IP addresses

**DNS Configuration:**
- **Add public IP** for Application Gateway
- **Create DNS A record** to resolve to Application Gateway

### Routing Rules Configuration

**Basic Routing Rule:**
- **Priority:** 1 (lower numbers processed first)
- **Listener:** Choose public endpoint
- **Listener type:** Basic
- **Error page URL:** Configure custom error pages
- **Backend settings:**
  - **Cookie-based affinity:** Disable (unless session stickiness required)
  - **Path-based routing:** Configure for complex routing scenarios

**Session Affinity Use Case:** When application requires user sessions to connect to same backend server

---

## Managing Web Application Firewall (WAF)

### WAF Configuration

**Navigation:** Resource → Application Gateway → WAF

**Policy Settings:**
- **Maximum upload size** - Configure file upload limits
- **Request timeout** - Set timeout values
- **Request body inspection** - Enable/disable body scanning

### Managed Rule Sets

**Available Rule Sets:**
- **OWASP (Open Web Application Security Project)** - Industry standard web security rules
- **Microsoft Bot Manager** - Bot detection and mitigation
- **Custom rules** - Organization-specific security rules

**Additional Features:**
- **Geo-location filtering** - Accept/deny traffic by country
- **Rate limiting** - Control request frequency
- **Custom exclusions** - Fine-tune rule behavior

---

## DDoS Protection

### DDoS Attack Detection

**Common Attack Indicators:**
- **Copious connection requests** from similar IPs within short timeframe
- **Abnormal traffic volume** resulting in slow network or server performance
- **Resource exhaustion** - CPU, memory, or bandwidth saturation

### DDoS Protection Plan

**Implementation Strategy:**
- **Create DDoS Protection Plan** - Use single plan across multiple subscriptions
- **Enable on VNet** - Associate protection plan with virtual networks
- **Cost Consideration** - May incur charges for protection services

**Protection Levels:**
- **Basic** - Automatic protection included with Azure platform
- **Standard** - Enhanced protection with attack analytics and alerting

---

## Working with User Defined Routes (UDRs)

### Route Table Architecture

**Traffic Flow:** Route Table → Subnet → Firewall

**Prerequisites:**
- Firewall resource deployed
- VNet and subnet configuration
- Route table creation and association

### Route Table Creation

**Creation Process:**
1. **Create Resource** → Search "Route Table"
2. **Configuration Options:**
   - **Propagate gateway routes:** Yes
   - **Purpose:** Automatically propagate learned routes from on-premises through VPN to Azure subnets

### User Defined Route Configuration

**Default Route Creation:**
1. **Navigate to route table** → Routes → Add Route
2. **Route Configuration:**
   - **Route name:** SendToFw1
   - **Address prefix:** 0.0.0.0/0 (IPv4 default route)
   - **Next hop type:** Virtual appliance
   - **Next hop address:** 10.0.0.4 (firewall private IP)

### Route Table Association

**Subnet Association:**
1. **Route table overview** → Subnets
2. **Associate subnet** with route table
3. **Select VNet and subnet**
4. **Result:** All outbound traffic from subnet resources sent to firewall private IP

---

## AZ-500 Practice Questions & Answers

### Question Set 1: Firewall Rules

**Q1: You are planning an Azure Firewall application rule to allow outbound access to www.skillsoft.com over 443. A colleague suggests a TCP 443 network rule instead. How should you respond?**
- ❌ While both methods will work, network rules are more secure because they will ensure the port 443 connection is using HTTP
- ❌ A network rule will not work
- ✅ **While both methods will work, application rules are more secure because they verify the HTTPS protocol to the FQDN**
- ❌ Neither will work; use DNAT

### Question Set 2: ASG Configuration

**Q2: Where can you specify an Application Security Group within an NSG rule?**
- ✅ **Source**
- ❌ Source port range
- ✅ **Destination**
- ❌ Destination port range

### Question Set 3: Firewall Network Rules

**Q3: Which properties are configured when creating an Azure Firewall network rule?**
- ✅ **Port number**
- ❌ Protocol number
- ❌ Protocol (HTTP or HTTPS)
- ✅ **Protocol (TCP or UDP)**

### Question Set 4: Load Balancer Benefits

**Q4: Which benefits do load balancers provide?**
- ✅ **Improved application performance under high loads**
- ❌ Enhanced application user sign-in security
- ✅ **Application high availability**
- ❌ Improved application performance under low loads

### Question Set 5: Firewall Rule Types

**Q5: Which type of Azure Firewall rule allows or blocks access to FQDNs?**
- ✅ **Application**
- ❌ DNAT
- ❌ SNAT
- ❌ Network

### Question Set 6: NAT Rules

**Q6: Which type of Azure Firewall rule maps a public IP:port to a private IP:port?**
- ✅ **DNAT rule**
- ❌ Network rule
- ❌ SNAT rule
- ❌ Application rule

### Question Set 7: DDoS Attacks

**Q7: Which common DDoS strategy is used against a victim network?**
- ❌ IP blackhole routing
- ❌ Rate throttling
- ❌ Ransomware
- ✅ **Network traffic flooding**

### Question Set 8: Default Routes

**Q8: Which notation is used for the IPv4 default route?**
- ❌ 127.0.0.1
- ✅ **0.0.0.0/0**
- ❌ ::0
- ❌ ::1

### Question Set 9: ASG vs NSG

**Q9: How are ASGs different from NSGs?**
- ✅ **ASGs can be used as destination groupings of VMs in NSG rules**
- ❌ They are the same thing
- ❌ NSGs can be used as a destination grouping of VMs in an ASG rule
- ❌ ASGs are built into Azure Firewall

### Question Set 10: Security Standards

**Q10: Which international non-profit group focuses on the Top 10 web application security risks?**
- ❌ NIST
- ❌ FedRAMP
- ✅ **OWASP**
- ❌ PCI DSS

---

## Key Takeaways for AZ-500

### Critical Concepts

**Application Security Groups:**
- Tag network interfaces with logical application roles
- Reference ASGs in NSG rules (source/destination) to avoid IP address management
- Scalable alternative to IP-based security rules
- Created as subscription-scoped resources

**Azure Firewall Architecture:**
- Requires dedicated "AzureFirewallSubnet" in VNet
- SNAT is implicit for all outbound traffic
- DNAT exposes internal services to external access
- Rule processing order: DNAT → Network → Application rules

**Application Gateway (WAF v2):**
- Layer 7 load balancer with advanced routing capabilities
- Path-based routing for complex application architectures
- Integrated WAF with OWASP rule sets
- Autoscaling capabilities for variable workloads

**DDoS Protection:**
- Standard plan provides enhanced protection and analytics
- Attaches to VNets for comprehensive coverage
- Consider cost versus risk assessment
- Monitor through Azure Metrics and Logs

**User Defined Routes:**
- Force-tunnel default route (0.0.0.0/0) to NVA or firewall
- Be aware of asymmetric routing issues
- Enable BGP route propagation when using VPN gateways
- Associate route tables with subnets, not individual resources

**Security Best Practices:**
- Use application rules over network rules for FQDN-based filtering
- Implement ASGs for scalable VM grouping in security rules
- Configure DDoS protection for internet-facing applications
- Plan UDR carefully to avoid routing loops
- Regular review of firewall rules and WAF policies