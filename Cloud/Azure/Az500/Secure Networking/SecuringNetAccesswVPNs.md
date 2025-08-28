# Securing Network Access with VPNs

## VPN Overview

### VPN Protocol Types

**Point-to-Point Tunneling Protocol (PPTP):**
- **Security Status:** Not considered secure
- **Legacy protocol** - avoid in production environments
- **Weak encryption** - vulnerable to modern attacks

**Layer 2 Tunneling Protocol (L2TP):**
- **Normally uses IPsec** for encryption
- **More secure** than PPTP
- **Common in enterprise** environments

**Secure Socket Layer (SSL)/Transport Layer Security (TLS):**
- **Firewall friendly** - uses TCP port 443
- **Browser-based access** - users access remote network resources through web browser
- **No client software** required for basic access

### VPN Connection Types

**Client-to-Site VPN:**
- **IP address assignment** from preconfigured pool
- **Additional IP configurations** appear on client device
- **Multi-factor authentication** support:
  - One-time codes
  - PKI certificates
  - Biometrics + username/password

**Point-to-Site VPN (Azure terminology):**
- **Client app installed** on endpoint device
- **Protocol support:** IPsec, SSTP, OpenVPN SSL/TLS
- **No customer VPN device** required on-premises
- **Use case:** Remote user device connectivity

**Site-to-Site VPN:**
- **Links on-premises to cloud** environments
- **VPN appliance** required on-premises side
- **Azure VNet Gateway** on cloud side
- **No VPN client** needed on end-user devices

---

## Point-to-Site VPN Configuration

### VPN Client Software

**Supported Clients:**
- **OpenVPN** - Cross-platform support
- **Windows native client** - Built-in Windows support
- **Configuration file** - .zip format containing client settings

**Important:** If any changes are made to Azure Gateway, download new configuration file

### Authentication Methods

**Client Certificate Authentication:**
- **PKI-based** authentication
- **Root certificate** uploaded to Azure Gateway
- **Client certificates** signed by root certificate
- **Most secure** option for P2S connections

---

## Generating VPN Certificates Using PowerShell

### Certificate-Based Authentication

**Use Case:** PKI certificate authentication to VPN gateway

### Root Certificate Generation

**PowerShell Command:**
```powershell
$cert = New-SelfSignedCertificate -Type Custom -KeySpec Signature -Subject "CN=RootCert" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsageProperty Sign -KeyUsage CertSign
```

**Certificate Storage:** `Cert:\CurrentUser\My` - Windows certificate storage location

### VPN Client Certificate Generation

**PowerShell Command:**
```powershell
New-SelfSignedCertificate -Type Custom -DnsName ClientCert -KeySpec Signature -Subject "CN=ClientCert" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" -Signer $cert -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
```

### Certificate Management

**Certificate Console Access:**
1. **Command:** `mmc` → Add snap-in → Certificates
2. **Expand:** Certificates (Current User) → Personal
3. **Import capability** available
4. **Note:** Self-signed certificates are not trusted by default

---

## Configuring Client VPNs

### VNet Gateway Creation

**Resource Creation:**
1. **All Resources** → Create → VNet Gateway
2. **Gateway Type:** VPN
3. **VPN Type:** Route-based (recommended)
   - **Policy-based** usually for IKE v1
4. **SKU:** Basic (unless availability zones needed)
5. **Generation:** Gen1 (unless high concurrent connectivity required)

### Network Configuration

**VNet Selection:** Choose existing virtual network
**Gateway Subnet:** Address range should auto-configure
**Public IP:** Create new public IP (e.g., "AzureVPN1PubIP")

### High Availability Options

**Active-Active Configuration:**
- **Enable** for high availability scenarios
- **Not required** for basic setups

**BGP Configuration:**
- **Configure** if using BGP routing
- **Optional** for most basic scenarios

### Point-to-Site Configuration

**Configuration Steps:**
1. **Navigate to VPN Gateway** → Point-to-Site Configuration
2. **Click "Configure Now"**
3. **Address Pool:** 192.168.5.0/24 (must not overlap with VNet or on-premises)

### Root Certificate Upload

**Certificate Export Process:**
1. **MMC** → Certificates snap-in → Personal → RootCert
2. **Right-click** → All Tasks → Export
3. **Select "No" to private key**
4. **Choose Base-64 encoded**
5. **Save as** RootCert.cer

**Certificate Data Upload:**
- **Copy content** between "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"
- **Paste into** Public Certificate Data field
- **Navigate away and back** to refresh interface
- **"Download VPN Client"** option will appear

### Client Installation

**Client Package:**
- **WindowsAmd64** directory contains VPN client executable
- **Install and configure** through Windows Settings → Network & Internet → VPN
- **Verify connection** using `ipconfig` command

---

## Configuring Site-to-Site VPNs

### Overview

Site-to-Site VPNs connect on-premises networks to Azure cloud environments.

**Required Components:**
- **VNet Gateway** (Azure side)
- **Local Network Gateway** (represents on-premises)

### Local Network Gateway Creation

**Resource Creation:**
1. **Resource** → Create → Search "Local Network Gateway"
2. **Name:** OnPremVpn1
3. **IP Address:** Public IP of on-premises VPN appliance
4. **Alternative:** FQDN in DNS that resolves to public IP

**Address Space Configuration:**
- **On-premises address space:** 192.168.1.0/24
- **Can use multiple prefixes**
- **BGP Settings:** Configure if on-premises uses BGP

### VPN Connection Configuration

**Connection Setup:**
1. **Azure VPN Gateway** → Properties → Connections → Add
2. **Connection Type:** Site-to-Site
3. **VNet Gateway:** Choose AzVPN1
4. **Local Network Gateway:** Choose created gateway
5. **Pre-Shared Key (PSK):** Enter shared secret
6. **IKE Version:** Leave default (IKE v1/v2)

### On-Premises Configuration

**Configuration Download:**
1. **VPN Connections** → Overview → Download Config
2. **Select device:** Vendor/Family/Firmware
3. **Provide configuration** to VPN technician

---

## Virtual WAN

### Overview

Virtual WAN provides software-defined wide area network (SD-WAN) capabilities in Azure Cloud.

**Key Features:**
- **Securely interconnects** branch office LANs
- **Hub and spoke architecture**
- **Traffic traverses** Azure backbone
- **Enterprise-scale** solution

### Architecture Considerations

**Regional Design:**
- **One Virtual Hub per region** for large enterprises
- **Central connection point** for multiple connection types:
  - Site-to-Site VPN
  - Point-to-Site VPN
  - ExpressRoute circuits

**Resource Replication:**
- **Virtual WAN resource** not replicated to secondary regions
- **Virtual Hubs and VPN Gateways** needed per region

### Virtual WAN SKUs

**Basic SKU:**
- **Site-to-Site VPN** connections
- **VPN to VNets** connectivity
- **Cost-effective** for simple scenarios

**Standard SKU:**
- **All Basic features** plus:
- **ExpressRoute** connectivity
- **Point-to-Site VPN** support
- **Virtual WAN hub** interconnectivity

### Hub Creation

**Hub Deployment:**
1. **Virtual WAN Overview** → Hubs → New
2. **Configure region** and networking settings
3. **Associate** connection types as needed

---

## ExpressRoute

### Overview

ExpressRoute provides private, dedicated WAN connectivity that does not traverse the internet.

**Key Benefits:**
- **Private dedicated circuit** - not over internet
- **No internet congestion** affecting performance
- **Predictable bandwidth** and latency
- **May use colocation provider** for connectivity

### ExpressRoute Requirements

**Prerequisites:**
- **Azure Subscription**
- **ExpressRoute Circuit** (Azure resource)
- **Route technician** configures on-premises router

**Service Provider Information:**
- **Provider:** Bell, telecom provider, etc.
- **Peering Location:** Local city connection point to Azure
- **Bandwidth:** 50 Mbps to 10 Gbps options

### ExpressRoute Implementation Process

**Implementation Steps:**
1. **Create ExpressRoute Circuit**
2. **Provide service key** to connectivity provider
3. **On-premises router** technician configures private WAN circuit
4. **Provider status** changes to "Provisioned" in portal
5. **Link VNets** to ExpressRoute circuit

**Service Key:** ExpressRoute GUID provided to service provider for circuit provisioning

### ExpressRoute Direct

**Use Cases:**
- **Large data transfers** requiring high bandwidth
- **Up to 100 Gbps** dual links
- **Private dedicated network** directly to Azure
- **Created within** Azure portal
- **Requires enrollment** email to Microsoft with site details

---

## Implementing ExpressRoute

### Regional Considerations

**Important:** Different countries/locations have specific rules - consult documentation

### ExpressRoute Circuit Creation

**Resource Creation:**
1. **Create Resource** → Search "ExpressRoute" → Create
2. **Region:** Choose closest to provider location

**Configuration Options:**
- **Provider:** Choose if you have connectivity provider
- **ExpressRoute Direct:** Not available everywhere - direct to Azure backbone
- **Peering Location:** Select appropriate location
- **Bandwidth:** 200 Mbps (duplex - 200 up/down)
- **Data Transfer:** No limit on data transfer amount

### SKU and Billing Options

**SKU Selection:**
- **Standard:** Access to local region only
- **Premium:** Global access capabilities

**Billing Options:**
- **Unlimited:** Outbound data unlimited
- **Metered:** Pay per GB for outbound data

### Circuit Provisioning

**Status Tracking:**
- **Circuit Status:** Enabled after creation
- **Service Key:** Provide to connectivity provider
- **Provider Status:** Monitor for "Provisioned" status

### Peering Configuration

**Peering Types:**
- **Private Peering:** For VNet connectivity
- **Microsoft Peering:** For Microsoft 365 services through ExpressRoute

**Layer 3 Routing:**
- **Provider-managed:** Provider configures routing
- **Self-managed:** Manual configuration required

### VNet Gateway for ExpressRoute

**Gateway Creation:**
- **Gateway Type:** ExpressRoute
- **Purpose:** Allow VNet connection from on-premises through ExpressRoute circuit
- **Required:** For VNet-to-ExpressRoute connectivity

---

## Configuring Private Endpoints

### Overview

Private Endpoints provide private IP connectivity to Azure PaaS services.

### Private Endpoint Creation

**Resource Creation:**
1. **Portal** → Search "Private Endpoints"
2. **Create NIC** (Network Interface Card)
3. **Name:** App1PrivateEndpointNIC

### Target Resource Configuration

**Resource Selection:**
- **Resource Type:** Microsoft.Web/sites (for web apps)
- **Choose target site**
- **Target Sub-resource:** Sites
- **Alternative:** Storage accounts or other PaaS services

### Network Configuration

**Subnet Selection:**
- **Choose subnet** for private IP assignment
- **Dynamic IP** assignment from subnet range
- **VNet integration** for private connectivity

### DNS Integration

**Private DNS Zone:**
- **Integrate with** Private DNS Zone
- **Automatic DNS** record creation
- **FQDN resolution** to private IP

### Verification Process

**DNS Verification:**
1. **Access VM** in same VNet
2. **Run nslookup** on service FQDN
3. **Verify non-authoritative** response shows private IP
4. **Confirm private connectivity** (not internet-based)

**Resource Verification:**
1. **Private Endpoint** → DNS Configuration
2. **Review private IP** and FQDN mapping
3. **VNet** → Connected Devices → Verify endpoint presence
4. **Command line** verification with `nslookup`

---

## AZ-500 Practice Questions & Answers

### Question Set 1: Private Endpoint Verification

**Q1: You configured a private endpoint for an Azure Web App. From a Windows VM, how do you verify private IP connectivity?**
- ✅ **nslookup**
- ❌ secedit
- ❌ ipconfig
- ❌ tcpdump

### Question Set 2: Certificate Generation

**Q2: Which PowerShell cmdlet generates a client VPN certificate?**
- ❌ Add-SelfSignedCertificate
- ❌ New-RootCertificate
- ❌ New-ClientCertificate
- ✅ **New-SelfSignedCertificate**

### Question Set 3: VPN Types

**Q3: Which VPN type does not require client software on endpoints?**
- ✅ **Site-to-site**
- ❌ Point-to-site
- ❌ IKEv2
- ❌ All VPN types require client software

### Question Set 4: Azure VPN Components

**Q4: Which Azure configuration represents the on-premises VPN appliance?**
- ❌ Private endpoint
- ❌ Public IP address
- ❌ Virtual network gateway
- ✅ **Local Network Gateway**

### Question Set 5: ExpressRoute Bandwidth

**Q5: For ExpressRoute 'Provider' port type, what is the maximum selectable bandwidth?**
- ❌ 50 Gbps
- ❌ 2 Gbps
- ❌ 10 Gbps
- ✅ **100 Gbps**

### Question Set 6: Point-to-Site Requirements

**Q6: Which Azure resource is required to set up a point-to-site VPN?**
- ✅ **Virtual network gateway**
- ❌ Private endpoint
- ❌ Customer gateway
- ❌ VNet

### Question Set 7: ExpressRoute Benefits

**Q7: What is a benefit of using ExpressRoute?**
- ❌ Access to more Azure services
- ❌ Use of a VPN tunnel
- ❌ Stronger network encryption
- ✅ **Predictable bandwidth**

### Question Set 8: Virtual WAN SKUs

**Q8: To ensure your Virtual WAN hub can connect to other hubs, which SKU is required?**
- ❌ Hybrid
- ❌ Basic
- ❌ Premium
- ✅ **Standard**

---

## Key Takeaways for AZ-500

### Critical Concepts

**VPN Protocol Security:**
- Prefer IKEv2/IPsec, OpenVPN, or SSTP (TCP/443) over PPTP
- PPTP is not considered secure for production use
- SSL/TLS VPN is firewall-friendly using standard HTTPS port

**Point-to-Site vs Site-to-Site:**
- **P2S** uses client software and certificates/Azure AD authentication
- **S2S** uses VPN appliance and Local Network Gateway representation
- **S2S** does not require client software on end-user devices

**Certificate Management:**
- Upload root certificate to Azure VPN Gateway
- Sign client certificates with root certificate
- Re-download client configuration package after gateway changes
- Use `New-SelfSignedCertificate` PowerShell cmdlet for certificate generation

**ExpressRoute Architecture:**
- Provides private, predictable bandwidth connectivity
- Choose appropriate peering types (Private/Microsoft) based on use case
- ExpressRoute Direct supports up to 100 Gbps bandwidth
- Service key (GUID) required for provider circuit provisioning

**Private Endpoints:**
- Map Azure PaaS services to private IP addresses
- Verify connectivity using `nslookup` inside the VNet
- Integrate with Private DNS zones for automatic DNS resolution
- Eliminates need for service-to-internet connectivity

**Security Best Practices:**
- Use certificate-based authentication for strongest P2S security
- Implement private endpoints for sensitive PaaS service connectivity
- Choose ExpressRoute for predictable, high-bandwidth requirements
- Regular certificate rotation and management procedures
- Monitor VPN connection status and performance metrics