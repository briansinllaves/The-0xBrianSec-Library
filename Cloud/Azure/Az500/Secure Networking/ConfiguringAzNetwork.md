# Configuring Azure Network

## Managing VNets Using the Portal

### Initial Setup Considerations

**Resource Group Planning:**
- Consider what resources you're working with when choosing resource group
- Plan for future resource dependencies and management

**IPv6 Configuration:**
- Can add IPv6 addressing for subnets
- IPv6 subnet format: `aaaa:bbbb:cccc:dddd::/64`
- IPv6 subnets are always /64

---

## Managing VNets Using the CLI

### Command Help and Discovery

**Available Commands:**
```bash
az network --help
az network vnet create --help
```

### VNet Creation

**Create VNet with Subnet:**
```bash
az network vnet create -g MyResourceGroup -n MyVnet --address-prefixes 192.0.0.0/16 --subnet-name MySubnet --subnet-prefixes 192.168.1.0/24
```

**Important:** Subnets must get their address blocks from the VNet address space

### VNet Information Commands

**Get VNet Names:**
```bash
az network vnet list --query [].name
```

**Show All Subnets in All VNets:**
```bash
az network vnet list --query [].subnets[].name
```
*Note: The `[]` syntax is used because we have a collection of subnet names in a collection of VNets*

### Subnet Management

**Create Subnet:**
```bash
az network vnet subnet create -g App1 --vnet-name vnet3 -n subnet2 --address-prefixes 192.168.2.0/24
```
*Where `-g` = resource group*

---

## Managing VNets Using PowerShell

### Command Discovery

**Find Available Commands:**
```powershell
Get-Command *virtualnetwork*
```

### VNet and Subnet Creation

**Create VNet with Subnet:**
```powershell
# Subnet configuration must fall within VNet range
$subnet = New-AzVirtualNetworkSubnetConfig -Name Subnet1 -AddressPrefix 30.0.1.0/24
$subnet
New-AzVirtualNetwork -ResourceGroupName App1 -Location eastus -Name vnet4 -AddressPrefix 30.0.0.0/16 -Subnet $subnet
```

### Adding Additional Subnets

**Planning:** Pre-plan address space - subnet needs to fit within VNet

**Add Subnet Process:**
```powershell
# Get reference stored to variable
$vnet = Get-AzVirtualNetwork -Name vnet4 -ResourceGroupName App1
Add-AzVirtualNetworkSubnetConfig -Name Subnet2 -VirtualNetwork $vnet -AddressPrefix "30.0.2.0/24"
# Commit changes using Set
$vnet | Set-AzVirtualNetwork
```

---

## Configuring Network Watcher

### Overview

**Navigation:** Search "Network Watcher" by region

**Capabilities:**
- Monitors traffic connection between components or between VNets
- Monitors components like VM interface in VNet reaching out to internet
- Can capture internet ingress network traffic
- Check routing problems

### Key Features

**Topology Monitoring:**
- **Navigation:** Monitoring → Topology
- Choose Azure subscription, resource group, VNet
- Visual representation of network components

**IP Flow Verify:**
- Test specific connectivity scenarios
- **Example:** Network interface, UDP, outbound, local IP `10.0.0.4:65000`, Remote IP `8.8.8.8:53`
- Determines allow/deny decisions

**Effective Security Rules:**
- View combined security rules from NSGs
- Shows resultant policy after rule evaluation

---

## Network Security Groups (NSGs)

### Overview

NSGs are Azure resources that can be associated with network interfaces and subnets to control traffic flow.

**Rule Types:**
- **Inbound rules** - Control traffic coming into resources
- **Outbound rules** - Control traffic leaving resources

### NSG Application Points

**Subnets:**
- Look at Network Security Group
- Rules applied to all VMs in the subnet

**Network Interfaces:**
- **Effective Security Rules** show combined rules
- Individual VM-level control

### Default Rules

**Built-in Rules:**
- **Load balancing** - Allow Azure Load Balancer traffic
- **Inter-VNet communications** - Allow traffic between peered VNets
- **Incoming internet traffic blocked** - Deny inbound from internet
- **Outbound internet traffic allowed** - Allow outbound to internet

### Rule Priority System

**Priority Values:**
- **Lower numbers = Higher priority**
- Custom rules: 100-4096
- **Default rules:** 65000+ (lowest priority)
- **Example:** Priority 300 gets checked before 65000, regardless of inbound/outbound

**Rule Actions:**
- **Allow** - Permit traffic
- **Deny** - Block traffic

### Traffic Flow Evaluation

**Inbound Traffic Path:**
1. **Subnet NSG** evaluated first
2. **Network Interface NSG** evaluated second

**Outbound Traffic Path:**
1. **Network Interface NSG** evaluated first
2. **Subnet NSG** evaluated second

---

## Managing NSGs Using the Portal

### Association Process

**Navigation:** `Portal.azure.com`

**Association Options:**
- **Interface level** - Click "Associate" button to tie NSG to network interface
- **Subnet level** - Click "Associate" button to tie NSG to subnet

**Multiple Ports:** When adding rule with multiple ports, format: `80,443,53`

---

## Managing NSGs Using the CLI

### Command Help

**Available Commands:**
```bash
az network --help
az network nsg --help
```

### NSG Management

**Create NSG:**
```bash
az network nsg create -g App1 -n App1NSG
```

**List NSGs:**
```bash
az network nsg list --query [].name
```

**Create Rule:**
```bash
az network nsg rule create -g App1 --nsg-name App1NSG -n Rule1 --priority 500 --source-address-prefixes 71.4.45.0/24 --destination-port-ranges 80 443 --destination-address-prefixes '*' --access Allow --protocol Tcp --description "Allow inbound HTTP and HTTPS traffic"
```

**Check Specific NSG Details:**
```bash
az network nsg show -g App1 --name App1NSG
```

---

## Managing NSGs Using PowerShell

### Command Discovery

**Find Available Commands:**
```powershell
Get-Command *networksecurity*
Get-Command *securityrule*
```

### Rule Creation

**Create Security Rule:**
```powershell
$rdp_allow_rule = New-AzNetworkSecurityRuleConfig -Name "allow-inbound-rdp" -SourcePortRange * -Protocol TCP -SourceAddressPrefix Internet -Access Allow -Priority 110 -Direction Inbound -DestinationPortRange 3389 -DestinationAddressPrefix *
```

**Check Rule Configuration:**
```powershell
$rdp_allow_rule
```

### NSG Creation and Association

**Create NSG:**
```powershell
$nsg = New-AzNetworkSecurityGroup -ResourceGroupName App1 -Location eastus -Name "Windows_Management_Rules" -SecurityRules $rdp_allow_rule
```

**Associate NSG to Subnet:**
```powershell
# Get VNet reference
$vnet = Get-AzVirtualNetwork -Name vnet3 -ResourceGroupName App1
# Associate NSG with subnet
Set-AzVirtualNetworkSubnetConfig -Name subnet1 -VirtualNetwork $vnet -AddressPrefix 192.168.1.0/24 -NetworkSecurityGroup $nsg
# Commit changes
$vnet | Set-AzVirtualNetwork
```

---

## VNet Peering

### Overview and Benefits

**Purpose:**
- Improve network performance and private IP connectivity
- Linking VNets together for seamless communication

**Scope:**
- VNets can be within or spread among Azure subscriptions
- VNets can span different regions
- **Status:** Peering is complete when peering status shows "Connected"

### Important Characteristics

**Non-Transitive:**
- If V1 ↔ V2 and V2 ↔ V3, then V1 cannot communicate with V3
- Must be explicitly peered together for communication

**Traffic Forwarding:**
- Can allow traffic forwarded from remote site (from VPN)
- Enable "Allow forwarded traffic" for hub-and-spoke scenarios

**Network Backbone:**
- Peered traffic stays on Azure global network backbone
- **Never goes over internet** - always private

**Cross-Cloud Support:**
- Works between Azure Public and Azure Government clouds

### Hub-and-Spoke Architecture

**Configuration:**
- All VNet connections set to "allow forwarded traffic"
- Central hub VNet connects to multiple spoke VNets
- Spokes communicate through hub

---

## Peering VNets Using the Portal

### Setup Process

**Prerequisites:** Have 2 VNets (e.g., app1-vnet, app2-vnet1)

**Configuration Steps:**
1. **Navigate:** VNets → Select VNet → Peering
2. **Peering Link Name:** app1vnet-To-App2vnet
3. **Gateway Settings:** No gateway for VPNs (unless using VPN gateway)
4. **Remote VNet Configuration:**
   - **Remote Peering Link Name:** App2vnet-To-App1vnet

**Critical:** Make sure you get both directions set up

### Management Operations

**Delete Peering:**
- Click 3 dots on the left side of peering entry
- Confirm deletion

**Functionality:**
- Peering allows routing from one IP space to different IP space
- Alternative: VPN could provide similar functionality but with different characteristics

---

## Peering VNets Using the CLI

### Variable Setup

**Create Variables for VNet IDs:**
```bash
vnet3=$(az network vnet show --resource-group App1 --name Vnet3 --query id --out tsv)
echo $vnet3
vnet4=$(az network vnet show --resource-group App1 --name Vnet4 --query id --out tsv)
echo $vnet4
```

### Command Help

**Available Commands:**
```bash
az network vnet --help
az network vnet peering --help
```

### Create Peering

**Link from Vnet3 to Vnet4:**
```bash
az network vnet peering create --name Vnet3ToVnet4 --resource-group App1 --vnet-name Vnet3 --remote-vnet $vnet4 --allow-vnet-access
```

**Link from Vnet4 to Vnet3:**
```bash
az network vnet peering create --name Vnet4ToVnet3 --resource-group App1 --vnet-name Vnet4 --remote-vnet $vnet3 --allow-vnet-access
```

---

## Peering VNets Using PowerShell

### VNet Reference Setup

**Get VNet References:**
```powershell
$vnet3 = Get-AzVirtualNetwork -Name Vnet3 -ResourceGroupName App1
$vnet3
$vnet4 = Get-AzVirtualNetwork -Name Vnet4 -ResourceGroupName App1
```

**Get VNet ID:**
```powershell
$vnet4.Id
```

### Create Peering Connections

**First Direction (Vnet3 to Vnet4):**
```powershell
Add-AzVirtualNetworkPeering -Name Vnet3-4 -VirtualNetwork $vnet3 `
    -RemoteVirtualNetworkId $vnet4.Id
```
*Note: This uses backtick (`) for line continuation*
*Optional: Add `| Out-Null` to suppress output*

**Second Direction (Vnet4 to Vnet3):**
```powershell
Add-AzVirtualNetworkPeering -Name Vnet4-3 -VirtualNetwork $vnet4 `
    -RemoteVirtualNetworkId $vnet3.Id
```

### Check Peering Status

**Get Peering State from VNet3 Perspective:**
```powershell
(Get-AzVirtualNetworkPeering -ResourceGroupName App1 -VirtualNetworkName Vnet3 | Select-Object PeeringState).PeeringState
```

---

## AZ-500 Practice Questions & Answers

### Question Set 1: VNet Peering Benefits

**Q1: What is the benefit of peering VNets together?**
- ❌ Peered VNet routing tables are merged and treated as one
- ✅ **Communication across VNets using private IP addresses**
- ❌ Inter-VNet traffic sent over Internet through VPN tunnel
- ❌ Communication across VNets using public IP addresses

### Question Set 2: Network Watcher Tools

**Q2: Which VNet monitoring tool should you use to check specific TCP port reachability from the Internet?**
- ❌ Packet capture
- ❌ Next hop
- ❌ NSG flow diagnostics
- ✅ **IP flow verify**

### Question Set 3: VNet Peering Traffic Control

**Q3: You plan on peering VNET1 to VNET2. A VPN connects on-premises to VNET1. Ensure traffic to VNET2 from VNET1 originated from VNET1.**
- ✅ **Block traffic that originates from outside the remote virtual network**
- ❌ Use the remote virtual network's gateway or Route Server
- ❌ Block all traffic to the remote virtual network
- ❌ Block traffic that originates from within the remote virtual network

### Question Set 4: CLI Commands

**Q4: You need to show all network security groups using CLI. Which command should you use?**
- ❌ az nsg list
- ✅ **az network nsg list**
- ❌ az vnet nsg list
- ❌ az network nsg get

### Question Set 5: NSG Association

**Q5: To which Azure resources can a network security group be directly associated?**
- ❌ Virtual machines
- ❌ RDS instances
- ✅ **Subnets**
- ✅ **Network interfaces**

### Question Set 6: PowerShell NSG Management

**Q6: Which PowerShell cmdlet is used to associate a network security group with a subnet?**
- ✅ **Set-AzVirtualNetworkSubnetConfig**
- ❌ Add-AzVirtualNetworkSubnetConfig
- ❌ New-AzNetworkSecurityGroup
- ❌ Add-AzVirtualNetworkSecurityGroup

### Question Set 7: Subnet Creation

**Q7: How can subnets be created using the portal?**
- ❌ Create the subnet within the existing virtual machine
- ❌ Create a new subnet resource
- ✅ **Create the subnet within the existing VNet**
- ❌ Create the subnet by uploading an ARM template

### Question Set 8: CLI Subnet Commands

**Q8: Which CLI command can be used to show subnets for a given VNet?**
- ✅ **az network vnet subnet list --resource-group App1 --vnet-name vnet3**
- ❌ az vnet network subnet list --resource-group App1 --vnet-name vnet3
- ❌ az network vnet subnet show --resource-group App1 --vnet-name vnet3
- ❌ az vnet subnet list --resource-group App1 --vnet-name vnet3

### Question Set 9: VNet Peering CLI

**Q9: Which CLI command peers VNets together?**
- ✅ **az network vnet peering create**
- ❌ az network create peer
- ❌ az network vnet show
- ❌ az vnet peer create

### Question Set 10: PowerShell Syntax Error

**Q10: What is wrong with the following PowerShell expression?**
```powershell
New-AzVirtualNetwork ... -AddressPrefix 30.0.0.0/64
```
- ❌ The 30 IP address range cannot be used with Azure VNets
- ❌ "CanadaEast" is not a valid Azure region
- ✅ **A /64 mask is not possible for IPv4 networks**
- ❌ There is no cmdlet named "New-AzVirtualNetwork"

### Question Set 11: NSG Rule Priority

**Q11: You have multiple NSG rules (allow SSH vs deny SSH). How do you control which rule is processed first?**
- ❌ Weight value
- ✅ **Priority number**
- ❌ DNS round robin
- ❌ You cannot control the rule processing order

### Question Set 12: PowerShell Peering Syntax

**Q12: Which PowerShell expression sets up one way of a VNet peering connection?**
- ❌ `Add-AzVirtualNetworkPeering -Name Vnet3-Vnet4 -VirtualNetwork $vnet3 -RemoteVirtualNetworkId "Vnet4"`
- ❌ `Add-AzVirtualNetworkPeering -Name Vnet3-Vnet4 -VirtualNetwork $vnet3 -RemoteVirtualNetworkId $vnet4`
- ❌ `Add-AzVirtualNetworkPeering -Name Vnet3-Vnet4 -VirtualNetwork "Vnet3" -RemoteVirtualNetworkId $vnet4.Id`
- ✅ **`Add-AzVirtualNetworkPeering -Name Vnet3-Vnet4 -VirtualNetwork $vnet3 -RemoteVirtualNetworkId $vnet4.Id`**

---

## Key Takeaways for AZ-500

### Critical Concepts

**VNet Planning:**
- Plan RFC1918 address blocks with future growth in mind
- Keep subnets within VNet prefixes
- IPv6 subnets are always /64

**NSG Evaluation Order:**
- **Lowest numeric priority first** (100 before 65000)
- **Inbound path:** Subnet → Network Interface
- **Outbound path:** Network Interface → Subnet
- Default rules have priority 65000+

**Network Watcher Tools:**
- **IP flow verify** - Test allow/deny for specific traffic
- **Effective security rules** - View combined NSG policies
- **Topology** - Visual dependency mapping

**VNet Peering Characteristics:**
- **Non-transitive** - A↔B and B↔C doesn't mean A↔C
- **Enable "allow forwarded traffic"** for hub-and-spoke with NVAs
- **Traffic stays on Microsoft backbone** - never goes over internet

**Command Syntax:**
- CLI uses `az network` prefix for networking commands
- PowerShell uses `$variable.Id` for resource references
- Backtick (`) used for PowerShell line continuation
- NSG association requires `Set-AzVirtualNetworkSubnetConfig`

**Security Best Practices:**
- Apply NSGs at both subnet and network interface levels
- Use priority numbers to control rule evaluation order
- Monitor effective security rules to verify intended behavior
- Plan peering relationships carefully for security boundaries