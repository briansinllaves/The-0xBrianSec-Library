

### Resource Group Information

#### Resource Group
- **ne**: [PentestTeam](https://portal.azure.com/#@ABCD.onmicrosoft.com/resource/subscriptions/14277680-2e31-4855-92e5-f337d3/resourceGroups/PentestTeam "PentestTeam")
- **Status**: Running
- **Location**: East US

#### Subscription
- **ne**: [PZI-zlop1-E-SUB308](https://portal.azure.com/#@ABCD.onmicrosoft.com/resource/subscriptions/14277680-2e31-4855-92e5-23rf "PZI-zlop1-E-SUB308")
- **ID**: 14277680-2e31-4855-92e5-fdbfb11337d3

#### Virtual Machine
- **Computer ne**: Proxy-2
- **Operating System**: Linux (Ubuntu 20.04)
- **Size**: Standard B2s (2 vCPUs, 4 GiB memory)
- **Public IP Address**: [4.157.64.71](https://portal.azure.com/#blade/HubsExtension/ResourceMenuBlade/id/%2Fsubscriptions%2F0-2e31-4855-92e5-fdbfb11337d3%2FresourceGroups%2FPentestTeam%2Fproviders%2FMicrosoft.Network%2FpublicIPAddresses%2FProxy-2-ip/menuid/configuration)
- **Private IP Address**: 10.1.1.1
- **Virtual Network/Subnet**: [Proxy-2-vnet/default](https://portal.azure.com/#blade/HubsExtension/ResourceMenuBlade/id/%2Fsubscriptions%2F14277680-2e31-4855-92e5-fdbfb11337d3%2FresourceGroups%2FPentestTeam%2Fproviders%2FMicrosoft.Network%2FvirtualNetworks%2FProxy-2-vnet "Proxy-2-vnet/default")
- **DNS ne**: [Not configured](https://portal.azure.com/#blade/HubsExtension/ResourceMenuBlade/id/%2Fsubscriptions%2F14277680-2e31-4855-92e5-fd7d3%2FresourceGroups%2FPentestTeam%2Fproviders%2FMicrosoft.Network%2FpublicIPAddresses%2FProxy-2-ip/menuid/configuration "Not configured")
- **Health State**: -

#### VM Details
- **VM Generation**: V2
- **VM Architecture**: x64
- **Agent Status**: Ready
- **Agent Version**: 2.11.1.4
- **Hibernation**: Disabled
- **Host Group**: -
- **Host**: -
- **Proximity Placement Group**: -
- **Colocation Status**: N/A
- **Capacity Reservation Group**: -
- **Disk Controller Type**: SCSI

#### Availability and Scaling
- **Availability Zone**: [(edit)](https://portal.azure.com/#)
- **Availability Set**: -
- **Scale Set**: -

#### Security
- **Security Type**: Trusted launch
- **Enable Secure Boot**: Enabled
- **Enable vTPM**: Enabled
- **Integrity Monitoring**: Disabled

#### Health Monitoring
- **Health Monitoring**: Not enabled

#### Extensions and Applications
- **Extensions**: -
- **Applications**: -

#### Networking
- **Public IP Address**:[ip](https://portal.azure.com/#)
- **Network Interface**: [proxy-26]
- **Public IP Address (IPv6)**: -
- **Private IP Address**: 10.1.1.1
- **Private IP Address (IPv6)**: -
- **Virtual Network/Subnet**: [Proxy-2-vnet/default]
- **DNS ne**: 

#### Size
- **Size**: Standard B2s
- **vCPUs**: 2
- **RAM**: 4 GiB

#### Source Image Details
- **Source Image Publisher**: Canonical
- **Source Image Offer**: 0001-com-ubuntu-server-focal
- **Source Image Plan**: 20_04-lts-gen2

#### Disk
- **OS Disk**: Proxy-2_OsDisk_1_db2094488347aad927d07
- **Encryption at Host**: Disabled
- **Azure Disk Encryption**: Not enabled
- **Ephemeral OS Disk**: N/A
- **Data Disks**: 0

#### Auto-shutdown
- **Auto-shutdown**: Not enabled
- **Scheduled Shutdown**: -

#### Azure Spot
- **Azure Spot**: -
- **Azure Spot Eviction Policy**: -

![[Pasted image 20240709175317.png]]
### Setup and Tools Configuration

#### Configure Virtual Network

1. **Allow SSH Inbound from VPN IP**:
   - Keep in mind that the VPN IP changes.
   ```bash
   az network nsg rule create \
     --resource-group YourResourceGroup \
     --nsg-ne YourNSGne \
     --ne AllowSSH \
     --protocol tcp \
     --priority 1000 \
     --destination-port-range 22 \
     --source-address-prefixes YourVPNIP \
     --access allow
   ```

#### Setup Proxy-2 VM in Proxy Net

1. **Setup SSH in VM**:
   - Ensure SSH is configured on the VM.
   ```bash
   sudo apt update
   sudo apt install openssh-server
   sudo systemctl enable ssh
   sudo systemctl start ssh
   ```

2. **Add Authorized SSH Keys**:
   - Edit the `~/.ssh/authorized_keys` file to add public SSH keys for users who need access.
   ```bash
   echo "ssh-rsa AAAAB3Nza... user@domain" >> ~/.ssh/authorized_keys
   ```

#### Configure Proxies and Add Tools

1. **Install nmap**:
   ```bash
   sudo apt install nmap
   ```

2. **Run nmap Scans**:
   ```bash
   nmap -vv -n -Pn -sT --top-ports 1000 -iL nessus_ips.txt --open -oA ./nmap_scans/nessus_ips_top1000

   nmap -vv -n -Pn -sT --top-ports 10000 -iL mssql_instances.txt -oA ./nmap_scans/mssql_top10000
   ```

3. **EyeWitness**:
   ```bash
   ./tools/EyeWitness/Python/EyeWitness.py -x ./nmap_scans/nessus_ips_top1000.xml -d ./eyewitness_reports/
   ./tools/EyeWitness/Python/EyeWitness.py -x ./nmap_scans/mssql_top10000.xml -d ./eyewitness_reports/mssql/
   ```

4. **SecLists**:
   - Use SecLists for common wordlists.

5. **ffuf**:
   ```bash
   ffuf -u https://ip/FUZZ -w /opt/SecLists/Discovery/Web-Content/big.txt -e .txt,.html,.js,.css,.xml,.aspx,.asp
   ```

6. **dirb**:
   ```bash
   dirb http://ip/ directory-list-2.3-big.txt
   ```

7. **Install Impacket**:
   ```bash
   sudo apt install python3-pip
   pip3 install impacket
   ```

8. **SSH Dynic Port Forwarding**:
   - Use SSH to create a dynic proxy.
   ```bash
   ssh -D 50050 -i ~/.ssh/proxy-2_key user@proxy-2
   ```

9. **Burp Suite**:
   - Proxy from home through SSH.
   - Run an active scan on `http://ip/report/`.