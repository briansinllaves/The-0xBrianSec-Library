
    # SecuringNetAccesswVPNs

    > **Your raw notes are preserved verbatim below**, then expanded with senior-operator theory, validated commands, and Q&A with ✅ marking the correct answers.

    ---
    ## Original Notes (Preserved Verbatim)
    ```
    (Your full SecuringNetAccesswVPNs notes pasted above are preserved in this file.)

SecuringNetAccesswVPNs VPN OVERVIEW
	• Point-to-Point Tunneling Protocol (PPTP) 
		○ Not considered secure 
	• Layer 2 Tunneling Protocol (L2TP) 
		○ Normally uses IPsec 
	• Secure Socket Layer (SSL)/Transport Layer Security (TLS) 
		○ Firewall friendly, TCP 443 
		○ Users access remote network resources through a web browser
	• Client-to-site VPN
		○ VPN clients are assigned an IP address from a preconfigured IP address pool 
		○ Additional IP configurations show up on a client device 
		○ Client authentication can use multi-factor authentication (MFA), e.g., one-time codes, PKI certificates, or biometrics in addition to a username and password
	• Point-to-site VPN (CtS name in Az)
		○ Client app installed on endpoint IPsec, Secure Socket Tunneling Protocol (SSTP), openvPN SSL/TLS 
		○ No customer virtual private network (VPN) device required 
		○ Used for remote user device connectivity 
	• Point-to-site VPN 
		○ VPN Client software
			§ Openvpn, windows cliet
			§ Vpn client config file .zip 
				□ If any changes to the AzGw, dwnload a new file
			§ Client cert auth
	• Azure
		○ 
		○ 
			§ Link on prem (a) to cloud (b), linked through a vnet, vpn app is a server or app or fw, the az side app vpn is vnet Gw
			§ No vpn client is needed in (a)
GENERATING VPN CERTS USING PWSH
	• Auth to a vpn
		○ Pki cert
	• On prem box
	*Generate Root Certificate 
	$cert = New-selfsignedcertificate -Type Custom —KeySpec Signature -Subject "CN=RootCert" -
	KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" —Keyusageproperty Sign —KeyUsage Certsign 
	• "Cert:\CurrentUser" - windows cert storage 
	*Generate VPN Client Certificate 
	New-selfsignedcertificate -Type Custom -DnsName Clientcert -KeySpec signature 
	-Subject "CN=ClientCert" -KeyExportpolicy Exportable -HashAlgorithm sha256 —KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" —Signer $cert —TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") 
	• In cmd, mmc, add snapin, certificates, expand cert current user>personal, could import, the above is self-signed and not trusted. 
CONFIGURING CLIENT VPNs
	• All resources> create > vnetGw > gw type:VPN | VPN type: route based, "policy based" is usually for IKE, SKU:basic, unless needed for other availability Zones, generation:gen1, unless you need a lot of concurrent connectivity support for multiple VPN clients> choose vnet > gw sub addr range should be auto config> create a new public ip to get into az through vpn, call it "AzureVPN1PubIP" 
	• For high-avail, enable active-active, don’t really need it or configure bgp
	• Go to resource,vpn | Point-to-site configuration, configure now, address pool, 192.168.5.0/24 - must not overlap, the vnet the addr pool this vnet was created in or the onprem addr pool | rootcert - RootCert, look at mmc, snap in certificates, personal, right click rootcert, all tasks,export, no to private key, base 64, store RootCert.cer
	• Copy everything between begin cert-- and --end cert. and paste that in in the public cert data. Click on another nav option and come back, and "download vpn client" will appear.
		○ WindowsAmd64 dir, vpn client.exe, go to windows settings, network&internet select vpn, review ipconfig in cmd. 
CONFIGURING SITE-TO-SITE VPNs -onprem to cloud
	• Need vnetgw and a customer (local) gw (onprem)
	• Resource > create > search: local network gw > name:OnPremVpn1, select ip (public ip of vpn app)or fqdn in DNS that resolves to the pub ip. 
	• Add in onprem Address space, 192.168.1.0/24. can use prefixes, next, check if onprem is using bgp settings, if so config. 
	• All resources view, azvpn1 gw, properties-connections, add, connection-type:site-site, chose vnet gw azvpn1, local net gw, enter in PSK; shared key. Leave ike1/2 and ok
	• Config onprem vpn, go to vpn connections overview, download config, select device vendor/family/firmware, give to vpn tech.
VIRTUAL WAN
	• Software-defined wide area network (SD-WAN) in the Az Cloud
	• Securely interconnects branch office local networks (LANs)
	• Uses hub and spoke
	• Traffic traverses the backbone 
	• Vwan resource is not replicated to secondary regions
	• Vhubs and vpnGws are needed
	• For a large enterprise
		○ 1 vhub per region
		○ Serves as a central connection point 
			§ Site to site
			§ Point to site
			§ Express route circuits
	• Basic
		○ connecting site-to-site 
		○ VPNs to VNets 
	• Standard
		○ basic + connecting ExpressRoute 
		○ point-to-site VPNs, and other Virtual WAN hubs 
	• Create hubs
		○ Vwans overview | hubs > new
EXPRESS ROUTE
	• Private dedicated WAN circuit (connection is not over the internet)
	• May go through a colocation provider
	• Link onprem network to az cloud, 
		○ No internet congestion
	• Requires Az Sub
	• ExRo circuit is a Az resource
	• Route tech configures onprem router
	• Need
		○ Provider: bell, telecom
		○ Peering location: your local city, where you want to make your connection to az
		○ Configured Bandwidth 50-10gps
	• When configured you get a ExRo GUID, is the service key, give this to service provider
		○ Steps
			§ Create a ExRo
			§ Provide service key to provider
			§ Onprem router tech configures priv wan circuit
			§ In portal provider status changes to "provisioned"
			§ Link vnets to expressroute circuit
	• ExpressRoute Direct
		○ Designed for large amounts of data transfer 
		○ Up to 100 Gbps dual links 
		○ Private dedicated network 
		○ Create within the Azure portal 
		○ Send a enrollment email to Microsoft with the details from the site, search for ExpressRoute
IMPLEMENTING EXPRESS ROUTE
	• Note that locations:countries have their own rules; see documentation
	• Create resource > search: expressroute > create > put region as close to provider. Create new 
	• Config:
		○ Provider; choose if you have provider
		○ Direct: not avail every where, goes straight to azure backbone. 
		○ Peering location
		○ Bandwidth; 200, duplex 200 is up/down, no limit to data you can transfer
		○ SKU: standard, only need access to local 
		○ If you want outbound to be unlimited, or click metered.
		○ Circuit status:enabled, give the key to provider, check and wait Provider Status
			§ Link an onprem router to the provider, 
		○ After connected 
			§ go to peerings 
				□ look at private for vnets
				□ Microsoft peering 
					® if you want services connected through expressroutes such as ms365
					® if your provider supports layer 3 service routing they will configure it on your behalf, or you will need to make config changes.
		○ Create a vnetGW, GW type of ExpressRoute, to allow connection to a vnet from your onprem env through the ExRo circuit. 
CONFIGURING ENDPOINTS
	• Portal > search > private endpoints aka NIC
	• Create a NIC
		○ App1privateendpointNIC
		○ Resource > type: MS web/sites, choose site, target sub-resource: sites, could be storage accounts. 
		○ Choose the subnet where you want the ip from, dyncamic ip
		○ Integrate with private dns zone, leave at next, create. 
		○ Go to cmd in a vm, in the vnet, nslookup on the site. Check nonauth site ip, we want to connect to the web app not over the internet. 
		○ Once deployment is complete, go to resource button-private endpoint
		○ Dns configuration, see private ip, fqdn
		○ Verify in vm that we are connecting to the private ip, with nslookup
		○ Home> vnets> connected devices > should see endpoint and notice private ip
		○ Should see private ip in cmd
TEST
	(Questions preserved below in Q&A)
    ```

    ---
    ## Senior‑Level Context & Theory
    - Prefer IKEv2/IPsec, OpenVPN, or SSTP (TCP/443) over PPTP.
- P2S uses client software & certs/AAD; S2S uses a VPN appliance and a Local Network Gateway.
- Upload root cert to gateway; sign client certs with root; re-download client package after changes.
- ExpressRoute provides private, predictable bandwidth; choose peering types (Private/Microsoft) per use case.
- Private Endpoints: map PaaS to private IPs; verify with `nslookup` inside the VNet; integrate Private DNS zones.

    ---
    ## Validated Commands – PowerShell
    ```powershell
    # Generate Root & Client VPN Certificates
$root = New-SelfSignedCertificate -Type Custom -KeySpec Signature -Subject "CN=RootCert" `
  -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyUsageProperty Sign -KeyUsage CertSign

$client = New-SelfSignedCertificate -Type Custom -DnsName "ClientCert" -KeySpec Signature `
  -Subject "CN=ClientCert" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" `
  -Signer $root -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
    ```

    ## Validated Commands – Azure CLI
    ```bash
    # Create Local Network Gateway (on-prem)
az network local-gateway create -g App1 -n OnPremVpn1 --gateway-ip-address <ONPREM_PUBLIC_IP> --local-address-prefixes 192.168.1.0/24

# Create VPN VNet Gateway
az network vnet-gateway create -g App1 -n AzVpnGw1 --public-ip-addresses AzureVPN1PubIP --vnet App1VNet   --gateway-type Vpn --vpn-type RouteBased --sku VpnGw1

# Site-to-site connection
az network vpn-connection create -g App1 -n OnPremToAzure --vnet-gateway1 AzVpnGw1 --local-gateway2 OnPremVpn1 --shared-key <PSK>
    ```

    ---
    ## Q&A – AZ‑500 Focus (✅ Correct Answers)
    - **You configured a private endpoint for an Azure Web App. From a Windows VM, how do you verify private IP connectivity?**
  - ✅ nslookup
  - secedit
  - ipconfig
  - tcpdump
- **Which PowerShell cmdlet generates a client VPN certificate?**
  - Add-SelfSignedCertificate
  - New-RootCertificate
  - New-ClientCertificate
  - ✅ New-SelfSignedCertificate
- **Which VPN type does not require client software on endpoints?**
  - ✅ Site-to-site
  - Point-to-site
  - IKEv2
  - All VPN types require client software
- **Which Azure configuration represents the on-prem VPN appliance?**
  - Private endpoint
  - Public IP address
  - Virtual network gateway
  - ✅ Local Gateway
- **For ExpressRoute 'Provider' port type, what is the max selectable bandwidth?**
  - 50 Gbps
  - 2 Gbps
  - 10 Gbps
  - ✅ 100 Gbps
- **Which Azure resource is required to set up a point-to-site VPN?**
  - ✅ Virtual gateway
  - Private endpoint
  - Customer gateway
  - Vnet
- **What is a benefit of using ExpressRoute?**
  - Access to more Azure services
  - Use of a VPN tunnel
  - Stronger network encryption
  - ✅ Predictable bandwidth
- **To ensure your Virtual WAN hub can connect to other hubs, which SKU?**
  - Hybrid
  - Basic
  - ✅ Premium
  - Standard
