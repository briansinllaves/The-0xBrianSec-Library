
    # ImplementAzNetSec

    > **Your raw notes are preserved verbatim below**, then expanded with senior-operator theory, validated commands, and Q&A with ✅ marking the correct answers.

    ---
    ## Original Notes (Preserved Verbatim)
    ```
    (Your full ImplementAzNetSec notes pasted above in the conversation are preserved in this file.)

ImplementAzNetSec APPLICATION SECURITY GROUPS (AGG)

	• Helps Group VMs together
	• 1 per app
	• Allows traffic to multiple apps/vms within a single subnet with different connectivity rules
	• Used in a NSG rule (source or destination)
	• Scales well, no need to reference IP address
	• Created in a Subscription and with resource group, is an instance. 
	• NSG references a ASG
		○ Example
			§ NSG - ssh 
				□ Source *, Destination is to a ASG

CONFIGURING ASG
	• Search for ASG in portals 
	• Create new, choose a Subscription and resource group, is an resource group instance.
	• To apply
		○ Go to each vm view, Networking > ASG tab and choose ASG
		○ Search NSG, choose Inbound sec rules, choose rule
			§ Dest. = ASG, choose which ASG
Az Fw and Fw Manager
	• can be created at config
		○ Requires a Vnet subnet named "AzureFirewallSubnet"
		○ Uses at least 1 static pub ip
	• Controls in/out traffic
	• Controls rule processing by priority
	• AzFw NAT
		○ SNAT
			§ Source NAT - outgoing traffic assumes the fw ip
			§ Configured by default
		○ DNAT
			§ Dest NAT - in traffic, translates pub web socket to resource private socket
			§ You configure
			§ NAT rule
				□ Name: Incoming-priorty-100
					® Incoming Http-tcp-dest addr (AzFwpubip:80) trans=dest.:80
	• Network Rules
		○ Applies to outbound
		○ Checked before application rule
		○ Not deeper inspection, looks at socket and protocol.
	• Application Rules
		○ All Domain Name System (DNS) fully qualified domain names (FQDNs) are blocked by default 
		○ Specify FQDNs 
		○ Wildcards are allowed, such as *.domain.com or * 
		○ Protocol:(HTTP or HTTPS) port, such as HTTPS:443; deep inspected, can enforce that the connection over port 443 to www.skillsoft.com is actually using the HTTP/S protocol
		○ Allow or Deny actions 
Managing Az Fw Application Rules
	• Create firewall
		○ Resource  > search az firewall > ms fw
		○ Choose subscription, resource, standard/premium=ssl termination-idps
		○ Address space , recommended 10.0.0.0/16, subnetaddr=10.0.1.0/24
		○ Enable forced network traffic, if you want it to go through a onprem network (like if you want it to go through a site-site vpn that links the firewall to that network-maybe you fw inspection apps on prem)
	• In overview, copy pub ip, rules (classic)
		○ Application rules
		○ List specific sites to allow
		○ Priority 100
		○ Skillsoft-ipaddr-*-https:443-www.skillsoft.com-add
Managing Az Fw Network Rules
	• Network rules get checked and enforce before application
	• Resources > fw > rules (classic)
	• DNAT
		○ RDPServer1-tcp-ipadd-Source=*dest.=fwpubip:3389-translatedaddr-privazvmip:3389
	• Bastions don’t have public ips. 
	• To connect to rdp, use the natted public ip of firewall that is mapped to the internal priv ip of the vm, not the public ip of the vm
Managing Az Fw Nat Rules
	• See above
	• Resources view> vnets> peer= app fw-firewall vnet
	• Check app fw, nothing is allowed out by default unless you start making allowances, even through rdp example
CONFIGURING Az APPLICATION GATEWAY
	• Really considered to be a web load balancer
	• Resource >marketplace> appgateway
	• Tier- wafv2,autoscaling,minimum=2, max=4,availzone=none, WAF policy=createnew-WAFPolicy1,Create vnet,  next, backend-add newpublicip-have dns a record resolve here. 
	• Add backend pool, point to app servics/vm,fqdns,none. 
	• Add routing rules, priority 1, listener, choose public. Listerner type=basic, error page url=no;backend setting, cookie-based affinity disable(relevance:you have an app and want the user session to be connected to the same backend server all the time.)
	•  path based routing
	• 
	• Now its ready to accept clients request
Managing Web Application Fw (WAF)
	• Resource>GW>Waf
		○ Policy settings
		○ Max upload size
		○ Managed rules, select OWASP & MS botmanager ruleset
		○ Can add geo location acceptance rule
DDOS PROTECTION
	• Detection
		○ Copious connection requests from similar Ips within a short time frame
		○ Abnormal volume of traffic resulting in slow net or server performance. 
		○ Create a "ddos protection plan" use a single plan across many subs.
		○ "In vnet, enable. May incur charges for its use
WORKING WITH USER DEFINED ROUTES (UDRs)
	• Route table > subnet -> firewall
	• Have fw resource,vnet-subnet
	• All resources > firewall > overview, private ip > vnet-subnet> look at route table
	• Create route table
		○ Create a resource > search > route table > 
			§ "Propagate gateway routes"=yes
				□ If we are going to link together various networks like onprem net through a vpn into azure, we are choosing if we want to automatically propagate learned routes to az subnets
	• Create table
		○ We must create 1 user defined route, click go to resource > left side "routes" > add route > routename=SendtoFw1, ip addre, 0.0.0.0/0 (ipv4 default), next hop addr=10.0.0.4, add
	• Associate the r.table
		○ In created route table overview
			§ Navigator-subnets, associate subnet
				□ Check, vnet,subnet,routetable
					® Any resources traffic in that subnet for az outbound will be sent to private ip of fw 
TEST
	(Questions preserved below in Q&A)
    ```

    ---
    ## Senior‑Level Context & Theory
    - **ASGs**: Tag NICs with logical app roles; reference ASGs in NSG rules (source/destination) to avoid IP churn.
- **Azure Firewall**: Needs `AzureFirewallSubnet`; SNAT is implicit for outbound; DNAT exposes internal services; rule order: DNAT ➜ Network ➜ Application.
- **App Gateway (WAF v2)**: Layer‑7 load balancer with path‑based routing, per‑site WAF policies (OWASP), autoscaling.
- **DDoS**: Standard plan attaches to VNets; enables telemetry/mitigation; consider cost vs. risk; alerts via Metrics/Logs.
- **UDRs**: Force‑tunnel 0.0.0.0/0 to NVA/firewall; mind asymmetric routing; enable BGP route propagation when appropriate.

    ---
    ## Validated Commands – PowerShell
    ```powershell
    # Create ASG and attach to NIC
$asg = New-AzApplicationSecurityGroup -Name WebASG -ResourceGroupName App1 -Location eastus
$nic = Get-AzNetworkInterface -Name vm1-nic -ResourceGroupName App1
$nic.IpConfigurations[0].ApplicationSecurityGroups += $asg
$nic | Set-AzNetworkInterface

# Route table + default route to NVA/Firewall
$rt = New-AzRouteTable -Name SendToFW -ResourceGroupName App1 -Location eastus -DisableBgpRoutePropagation $false
Add-AzRouteConfig -Name DefaultToFW -AddressPrefix 0.0.0.0/0 -NextHopType VirtualAppliance -NextHopIpAddress 10.0.0.4 -RouteTable $rt | Out-Null
Set-AzRouteTable -RouteTable $rt
    ```

    ## Validated Commands – Azure CLI
    ```bash
    # Create ASG
az network asg create -g App1 -n WebASG

# Attach ASG to NIC (first IP config)
asg_id=$(az network asg show -g App1 -n WebASG --query id -o tsv)
az network nic update -g App1 -n vm1-nic --add ipConfigurations[0].applicationSecurityGroups $asg_id

# Route table and default route
az network route-table create -g App1 -n SendToFW --disable-bgp-route-propagation false
az network route-table route create -g App1 --route-table-name SendToFW -n DefaultToFW   --address-prefix 0.0.0.0/0 --next-hop-type VirtualAppliance --next-hop-ip-address 10.0.0.4
    ```

    ---
    ## Q&A – AZ‑500 Focus (✅ Correct Answers)
    - **You are planning an Azure Firewall application rule to allow outbound access to www.skillsoft.com over 443. A colleague suggests a TCP 443 network rule instead. How should you respond?**
  - While both methods will work, network rules are more secure because they will ensure the port 443 connection is using HTTP.
  - A network rule will not work
  - ✅ While both methods will work, application rules are more secure because they verify the HTTPS protocol to the FQDN.
  - Neither will work; use DNAT
- **Where can you specify an Application Security Group within an NSG rule?**
  - Source
  - Source port range
  - ✅ Destination
  - Destination port range
- **Which properties are configured when creating an Azure Firewall network rule?**
  - Port number
  - Protocol number
  - Protocol (HTTP or HTTPS)
  - ✅ Protocol (TCP or UDP)
- **Which benefits do load balancers provide?**
  - Improved application performance under high loads
  - Enhanced application user sign-in security
  - ✅ Application high availability
  - Improved application performance under low loads
- **Which type of Azure Firewall rule allows or blocks access to FQDNs?**
  - ✅ Application
  - DNAT
  - SNAT
  - Network
- **Which type of Azure Firewall rule maps a public IP:port to a private IP:port?**
  - ✅ DNAT rule
  - Network rule
  - SNAT rule
  - Application rule
- **Which common DDoS strategy is used against a victim network?**
  - IP blackhole routing
  - Rate throttling
  - Ransomeware
  - ✅ Network traffic flooding
- **Which notation is used for the IPv4 default route?**
  - 127.0.0.1
  - ✅ 0.0.0.0/0
  - ::0
  - ::1
- **How are ASGs different from NSGs?**
  - ✅ ASGs can be used as destination groupings of VMs in NSG rules
  - They are the same thing
  - NSGs can be used as a destination grouping of VMs in an ASG rule
  - ASGs are built into Azure Firewall
- **Which international non-profit group focuses on the Top 10 web application security risks?**
  - NIST
  - FedRAMP
  - ✅ OWASP
  - PCI DSS
