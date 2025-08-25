
    # ConfiguringAzNetwork

    > **Your raw notes are preserved verbatim below**, then expanded with senior-operator theory, validated commands, and Q&A with ✅ marking the correct answers.

    ---
    ## Original Notes (Preserved Verbatim)
    ```
    Secure networking ConfiguringAzNetwork Managing Vnets using the portal start at 3:18

	• In setup, when choosing the resource group, consider what resources your are working with
	• If you want Add another ipv6 for the subnet aaaa:bbbb:cccc:dddd::/64 

Managing Vnets using the CLI
	• Check az network commands
		○ Az network --help
		○ Az network vnet create --help

	• Create a vnet
		○ Az network vnet create -g MyResourceGroup -n MyVnet --address-prefix 192.0.0/16 --subnet-name MySubnet --subnet-prefixes 192.168.1.0/24
	• Subnets must get there address blocks from the Vnet

	• Get Vnet names
		○ Az network vnet list --query [].name

	• Show all subnets in all vnets
		○ Az network vnet list --query [].subnets[].name            
			§ The [] because we have a collection of subnet names in a collection of vnets

	• Create subnet
		○ Az network vnet subnet create -g App1 --vtnet-name vnet3 -n subnet2 --address-prefixes 192.168.2.0/24
			§ -g = resource group


Managing Vnets using Powershell
	• Get-commmand *virtualnetwork*

	• Create a vnet and subnet
		○ Subnet config must fall in vnet range
		○ $subnet = NewAzVirtualNetworkSubnetConfig -name Subnet1 -AddressPrefix 30.0.1.0/24
		○ $subnet
		○ NewAzVirtualNetwork -ResourceGroupName App1 -Location USEast -name vnet4 -AddressPrefix 30.0.0.0/16 -Subnet $subnet 

	• Add another subnet
		○ Preplan address space, sub needs to fit in vnet
		○ Get a reference stored to a variable
		○ $vnet=Get-AzVirtualNetwork -name vnet4
		○ Add-AzVirtualNetworkSubnetConfig -Name Subnet2 -VirtualNetwork $vnet -AddressPrefix "30.0.2.0/24"
		○ Commit by using Set
			§ $vnet | Set-AzVirtualNetwork


Configuring Network Watcher
	• Search Network Watcher, by given region
	• Monitors traffic connection between componets or between vnets, or componets like a vm interface in a vnet reaching out to the internet or the opposite. 
	• You can capture internet ingress net traffic.
	• Check routing problems
	• Monitoring | Topolgy, choose az sub, resource group, vnet
	• Ip flow verify
		○ Netint, udp, outbound, local ip 10.0.0.4:65000 RemoteIP:8.8.8.8:53
	• See Effective security rules

Network Security Groups (NSG)
	• Azure resources that be associated with netints and subnets
	• Rules for in/outbound
	• Subnets
		○ Look at network security group, rules applied to all vms in the subnet
	• Network interfaces
		○ Effective sec rules
			§ Inbound rules
	• Default rules
		○ Load balancing 
		○ Inter-vnet comms
		○ Incoming internet traffic blocked
		○ Outbound internet traffic allowed
	• RulePriority value
		○ When you create a rule, assign a priority value that is smaller than the defaults 65000, a 300 would get checked first regardless of in/out
			§ So lower has more priority
	• Rule Actions allows/Deny
	• Can apply NSGs to subnets and interfaces
		○ Traffic inbound will get checked at subnet first then interface
		○ Traffic outbound will get checked at interface then subnet

Managing NSGs Using the portal
	• Portal.azure.com
	• Either in interface or subnet, "associate" button will tie to the nsg
	• When adding a rule with 1+ ports, do it like 80,443,53

Managing NSGs Using the CLI
	• Get command help
		○ Az network --help
		○ Az network nsg --help

	• Create a NSG
		○ Az network nsg create -g App1 -n App1NSG

	• List nsg
		Az network nsg list --query [].name

	• Create a rule
		○ Az network rule nsg create -g App1 --nsg-name App1NSG -n Rule1 --priority 500 --source-address-prefixes 71.4.45.0/24 --destination-port-ranges 80 443 --destination-address-prefixes '*' --access Allow --protocol Tcp --description "Allow inbound HTTP and HTTPS traffic"

	• Check detail of specific nsg
		○ Az network nsg list -g app1 --nsg-name app1nsg



Managing NSGs Using Powershell

	• Command help
		○ Get-command *networksecurity*
		○ Get-command *securityrule*

	• Create rule
		○ $rdp_allow_rule= New-AzNetworkSecurityRuleConfig -Name "allow-inbound-rdp" -SourcePortRange * -Protocol TCP -SourceAddressPrefix Internet -Access Allow -Priority 110 -Direction Inbound -DestinationPortRange 3389 -DestinationAddressPrefix * 
	• Check rule is set
		○ $rdp_allow_rule

	• Create NSG
		○ $nsg = New-AzNetworkSecurityGroup -ResourceGroupName App1 -Location eastus -Name "Windows_Management_Rules" -SecurityRules $rdp_allow_rule
			§ We need to set this to a subnet or an interface
				□ Get-command *networksubnetconfig*
				□ Create virt net
					® $vnet=Get-AzVirtualNetwork -name vnet3 -resourcegroupname app1
			§ $nsg
				□ Set-AzVirtualNetworkSubnetConfig -Name subnet1 -VirtualNetwork $vnet -AddressPrefix 192.168.1.0/24 -NetworkSecurityGroup $nsg
			§ $vnet | Set-AzVirtualNetwork

Vnet peering
	• Improve network performance and private ip connectivity
	• Linking vnets together
	• Vnets can be within or spread among az subs, regions
	• Peering is complete when the peering status says "connected"
	• Vnet peering is not transitive if v1<->v2 & v2<->v2, cant v1<->v3 (have to be peered together)
	• Can allow traffic forwarded from remote site (from a vpn)
	• Note between clouds (az pub and az gov)
	• Peered traffic stays on az global network backbone, never goes out over the internet
	• Hub and spoke vnet peering
		○ All of the vnet connectinos would be set to allow forwarded traffic
	• 
Peering Vnets using the portal 
	• Have 2 vnets, app2-vnet1
	• Vnets > net > peering,
	• Name peering link : app1vnet-To-App2vnet
	• No gw for vpns
	• Name the remote vnet
		○ Peering link name - for traffic coming into the opposite way
			§ App2vnet-To-App1vnet
	• MAKE SURE YOU GET BOTH SETUP
	• To Delete
		○ 3 dots on the left
	• Peering allows routing from 1 ip space to a different ip space
		○ A vpn could do that. 
Peering Vnets using the CLI
	• bash
	• Create 2 vnets
		○ Vnet3=$(az network vnet show --resource-group App1 --name Vnet3 --query id --out tsv)
		○ Echo $vnet3
	• Do it again with the peer
		○ Vnet4=$(az network vnet show --resource-group App1 --name Vnet4 --query id --out tsv)
		○ Echo $vnet4
Create peering
	• Az network vnet --help
	• Az network vnet peering --help
	• Link from 3 to 4
		○ Az network vnet peering create --name Vnet3ToVnet4 --resource-group App1 --vnet-name Vnet3 --remote-net $vnet4 --allow-vnet-access
	• Link from 4 to 3
		○ Az network vnet peering create --name Vnet4ToVnet3 --resource-group App1 --vnet-name Vnet4 --remote-net $vnet3 --allow-vnet-access
Peering Vnets using powershell
	• $vnet3 = Get-AzVirtualNetwork -Name Vnet3 -ResourceGroupName App1
		○ $vnet3
	• $vnet4 = Get-AzVirtualNetwork -Name Vnet4 -ResourceGroupName App1
Need id
	• $vnet.id
	• Add-AzVirtualNetworkPeering -Name Vnet3-4 -VirtualNetwork $vnet3 `
	>> -RemoteVirtualNetworkID $vnet4.Id 
		○ This is a backtick
		○ Can add | Out-Null
	• Now the other side

		○ Add-AzVirtualNetworkPeering -Name Vnet4-3 -VirtualNetwork $vnet4 `
		>> -RemoteVirtualNetworkID $vnet3.Id 
	• Get peering state from perspective vnet3
	• (Get-AzVirtualNetworkPeering -ResourceGroupName App1 -VirtualNetworkName Vnet3 | Select PeeringState).PeeringState
	• Changed # to see reverse
TEST
... (full test questions preserved in Q&A below) ...
    ```

    ---
    ## Senior‑Level Context & Theory
    - **Addressing**: Plan RFC1918 blocks with future growth; keep subnets within VNet prefixes. IPv6 subnets are /64.
- **NSG evaluation**: Lowest numeric priority first; defaults (65000+) last. Inbound path: Subnet ➜ NIC; Outbound: NIC ➜ Subnet.
- **Network Watcher**: Use *IP flow verify* to test allow/deny, *Effective security rules* to view resultant policy, *Topology* for dependency maps.
- **Peering**: Non‑transitive. Enable *allow forwarded traffic* when using NVAs in hub‑and‑spoke. Peered traffic stays on the Microsoft backbone.

    ---
    ## Validated Commands – PowerShell
    ```powershell
    # Create VNet + Subnet
$sub = New-AzVirtualNetworkSubnetConfig -Name Subnet1 -AddressPrefix 30.0.1.0/24
New-AzVirtualNetwork -ResourceGroupName App1 -Location eastus -Name vnet4 -AddressPrefix 30.0.0.0/16 -Subnet $sub

# Add another subnet
$vnet = Get-AzVirtualNetwork -Name vnet4 -ResourceGroupName App1
Add-AzVirtualNetworkSubnetConfig -Name Subnet2 -VirtualNetwork $vnet -AddressPrefix 30.0.2.0/24
$vnet | Set-AzVirtualNetwork

# NSG and rule, attach to subnet
$rule = New-AzNetworkSecurityRuleConfig -Name allow-inbound-rdp -Access Allow -Protocol Tcp -Direction Inbound `
  -Priority 110 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 3389
$nsg  = New-AzNetworkSecurityGroup -ResourceGroupName App1 -Location eastus -Name Windows_Management_Rules -SecurityRules $rule
$vnet = Get-AzVirtualNetwork -Name vnet3 -ResourceGroupName App1
Set-AzVirtualNetworkSubnetConfig -Name subnet1 -VirtualNetwork $vnet -AddressPrefix 192.168.1.0/24 -NetworkSecurityGroup $nsg
$vnet | Set-AzVirtualNetwork

# Peering
$v3 = Get-AzVirtualNetwork -Name Vnet3 -ResourceGroupName App1
$v4 = Get-AzVirtualNetwork -Name Vnet4 -ResourceGroupName App1
Add-AzVirtualNetworkPeering -Name Vnet3-4 -VirtualNetwork $v3 -RemoteVirtualNetworkId $v4.Id | Out-Null
Add-AzVirtualNetworkPeering -Name Vnet4-3 -VirtualNetwork $v4 -RemoteVirtualNetworkId $v3.Id | Out-Null
(Get-AzVirtualNetworkPeering -ResourceGroupName App1 -VirtualNetworkName Vnet3 | Select-Object PeeringState).PeeringState
    ```

    ## Validated Commands – Azure CLI
    ```bash
    # Create VNet + Subnet
az network vnet create -g MyResourceGroup -n MyVnet --address-prefixes 192.0.0.0/16   --subnet-name MySubnet --subnet-prefixes 192.168.1.0/24

# List VNets and subnets
az network vnet list --query [].name
az network vnet list --query [].subnets[].name

# Create subnet
az network vnet subnet create -g App1 --vnet-name vnet3 -n subnet2 --address-prefixes 192.168.2.0/24

# NSG + rule
az network nsg create -g App1 -n App1NSG
az network nsg rule create -g App1 --nsg-name App1NSG -n Rule1 --priority 500   --source-address-prefixes 71.4.45.0/24 --destination-port-ranges 80 443   --destination-address-prefixes '*' --access Allow --protocol Tcp   --description "Allow inbound HTTP and HTTPS traffic"
az network nsg list --query [].name

# Peering
vnet3=$(az network vnet show -g App1 -n Vnet3 --query id -o tsv)
vnet4=$(az network vnet show -g App1 -n Vnet4 --query id -o tsv)
az network vnet peering create -g App1 --vnet-name Vnet3 -n Vnet3ToVnet4 --remote-vnet $vnet4 --allow-vnet-access
az network vnet peering create -g App1 --vnet-name Vnet4 -n Vnet4ToVnet3 --remote-vnet $vnet3 --allow-vnet-access
    ```

    ---
    ## Q&A – AZ‑500 Focus (✅ Correct Answers)
    - **What is the benefit of peering vnets together?**
  - Peered vnet routing tables are merged and treated as one
  - ✅ Communication across vnets using private IP addresses
  - Inter-vnet traffic sent over the Internet through a VPN tunnel
  - Communication across vnets using public IP addresses
- **Which vnet monitoring tool should you use to check a specific TCP port reachability from the Internet?**
  - Packet capture
  - Next hop
  - NSG flow diagnostics
  - ✅ IP flow verify
- **You plan on peering VNET1 to VNET2. A VPN connects on-prem to VNET1. Ensure traffic to VNET2 from VNET1 originated from VNET1.**
  - ✅ Block traffic that originates from outside the remote virtual network
  - Use the remote virtual network’s gateway or Route Server
  - Block all traffic to the remote virtual network
  - Block traffic that originates from within the remote virtual network
- **You need to show all network security groups using the CLI. Which command should you use?**
  - az nsg list
  - ✅ az network nsg list
  - az vnet nsg list
  - az network nsg get
- **To which Azure resources can a network security group be directly associated?**
  - Virtual machines
  - RDS instances
  - ✅ Subnets
  - Network interfaces
- **Which PowerShell cmdlet is used to associate a network security group with a subnet?**
  - ✅ Set-AzVirtualNetworkSubnetConfig
  - Add-AzVirtualNetworkSubnetConfig
  - New-AzNetworkSecurityGroup
  - Add-AzVirtualNetworkSecurityGroup
- **How can subnets be created using the portal?**
  - Create the subnet within the existing virtual machine
  - Create a new subnet resource
  - ✅ Create the subnet within the existing vnet
  - Create the subnet by uploading an ARM template
- **Which CLI command can be used to show subnets for a given vnet?**
  - ✅ az network vnet subnet list --resource-group App1 --vnet-name vnet3
  - az vnet network subnet list --resource-group App1 --vnet-name vnet3
  - az network vnet subnet show --resource-group App1 --vnet-name vnet3
  - az vnet subnet list --resource-group App1 --vnet-name vnet3
- **Which CLI command peers vnets together?**
  - ✅ az network vnet peering create
  - az network create peer
  - az network vnet show
  - az vnet peer create
- **What is wrong with the following PowerShell expression?  New-AzVirtualNetwork ... -AddressPrefix 30.0.0.0/64**
  - The 30 IP address range cannot be used with Azure vnets
  - “CanadaEast” is not a valid Azure region
  - ✅ A /64 mask is not possible
  - There is no cmdlet named “New-AzVirtuaNetwork”
- **You have multiple NSG rules (allow SSH vs deny SSH). How do you control which rule is processed first?**
  - Weight value
  - ✅ Priority number
  - DNS round robin
  - You cannot control the rule processing order
- **Which PowerShell expression sets up one way of a vnet peering connection?**
  - Add-AzVirtualNetworkPeering -Name Vnet3-Vnet4 -VirtualNetwork $vnet3 -RemoteVirtualNetworkId “Vnet4”
  - Add-AzVirtualNetworkPeering -Name Vnet3-Vnet4 -VirtualNetwork $vnet3 -RemoteVirtualNetworkId $vnet4
  - Add-AzVirtualNetworkPeering -Name Vnet3-Vnet4 -VirtualNetwork “Vnet3” -RemoteVirtualNetworkId $vnet4.Id
  - ✅ Add-AzVirtualNetworkPeering -Name Vnet3-Vnet4 -VirtualNetwork $vnet3 -RemoteVirtualNetworkId $vnet4.Id
