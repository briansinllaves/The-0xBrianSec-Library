### Leveraging Public Information to Access Cloud Infrastructure

#### Azure

1. **Enumerating Azure Resources**:
   - Use Azure CLI to enumerate resources related to ABCD.
   - **List All Resources**:
     ```bash
     az resource list --query "[?contains(ne, 'ABCD')]" -o table
     ```
     - **Explanation**:
       - `az resource list`: Lists all resources in the subscription.
       - `--query "[?contains(ne, 'ABCD')]"`: Filters resources with 'ABCD' in their ne.
       - `-o table`: Outputs results in a table format.

2. **Enumerating Virtual Machines**:
   - **List VMs**:
     ```bash
     az vm list --query "[?contains(resourceGroup, 'ABCD')].{ne:ne, PublicIP:publicIps, PrivateIP:privateIps}" -o table
     ```
     - **Explanation**:
       - `az vm list`: Lists all virtual machines.
       - `--query "[?contains(resourceGroup, 'ABCD')].{ne:ne, PublicIP:publicIps, PrivateIP:privateIps}"`: Filters VMs in resource groups containing 'ABCD'.
       - `-o table`: Outputs results in a table format.

3. **Checking Public Azure Buckets and Services**:
   - **List Storage Accounts with Public Access**:
     ```bash
     az storage account list --query "[?properties.publicNetworkAccess=='Enabled' && contains(ne, 'ABCD')].{ne:ne, ResourceGroup:resourceGroup}" -o table
     ```
     - **Explanation**:
       - `az storage account list`: Lists all storage accounts.
       - `--query "[?properties.publicNetworkAccess=='Enabled' && contains(ne, 'ABCD')].{ne:ne, ResourceGroup:resourceGroup}"`: Filters storage accounts with public access enabled and containing 'ABCD' in their nes.
       - `-o table`: Outputs results in a table format.

4. **Azure Resource Graph Explorer**:
   - Use the Azure Resource Graph Explorer to query and gather information on resources related to ABCD.
     - **Example Query**:
       ```kql
       resources
       | where contains(resourceGroup, 'ABCD')
       | project ne, location, type, resourceGroup
       ```
       - **Explanation**:
         - `resources`: Queries all resources.
         - `where contains(resourceGroup, 'ABCD')`: Filters resources in resource groups containing 'ABCD'.
         - `project ne, location, type, resourceGroup`: Selects specific properties to display.

5. **Using MicroBurst for Azure Reconnaissance**:
   - **MicroBurst Setup**:
     ```bash
     git clone https://github.com/NetSPI/MicroBurst.git
     cd MicroBurst
     ```
   - **Enumerate Subdomains**:
     ```powershell
     Import-Module ./MicroBurst.psm1
     Invoke-EnumerateAzureSubDomains -Base ABCD.com
     ```
     - **Explanation**:
       - `Invoke-EnumerateAzureSubDomains -Base ABCD.com`: Enumerates subdomains for the base domain `ABCD.com`.

6. **Using LAVA for Azure Penetration Testing**:
   - **LAVA Setup**:
     ```bash
     git clone https://github.com/mattrotlevi/lava.git
     cd lava
     pip install -r requirements.txt
     ```
   - **Enumerate Azure Resources Using LAVA**:
     ```bash
     python3 lava.py --list-resources --resource-group ABCDResourceGroup
     ```
     - **Explanation**:
       - `--list-resources`: Lists resources in the specified resource group.
       - `--resource-group ABCDResourceGroup`: Specifies the resource group to enumerate.
   - **Checking for Publicly Exposed Services**:
     ```bash
     python3 lava.py --public-services --resource-group ABCDResourceGroup
     ```
     - **Explanation**:
       - `--public-services`: Lists publicly exposed services in the specified resource group.
       - `--resource-group ABCDResourceGroup`: Specifies the resource group to check.

7. **Azure Load Balancer**:
   - Identify backend instances by examining the configuration of load balancers in Azure.
   - **Example Command**:
     ```bash
     az network lb show --ne ABCDLoadBalancer --resource-group ABCDResourceGroup --query 'backendAddressPools[0].backendIpConfigurations'
     ```
     - **Explanation**:
       - `az network lb show --ne ABCDLoadBalancer --resource-group ABCDResourceGroup`: Shows the details of the specified load balancer.
       - `--query 'backendAddressPools[0].backendIpConfigurations'`: Filters to show backend IP configurations.

#### AWS

1. **Pacu Setup**:
   - Pacu is an open-source AWS exploitation framework designed for offensive security testing.
   - **Setup**:
     ```bash
     git clone https://github.com/RhinoSecurityLabs/pacu.git
     cd pacu
     bash install.sh
     ```

2. **Using AWS CLI for Public Information**:
   - **List Buckets**:
     ```bash
     aws s3api list-buckets --query "Buckets[?contains(ne, 'ABCD')].ne"
     ```
     - **Explanation**:
       - `aws s3api list-buckets`: Lists all S3 buckets.
       - `--query "Buckets[?contains(ne, 'ABCD')].ne"`: Filters the list to show only bucket nes containing 'ABCD'.

3. **Using CloudMapper for AWS Reconnaissance**:
   - **CloudMapper Setup**:
     ```bash
     git clone https://github.com/duo-labs/cloudmapper.git
     cd cloudmapper
     pip install -r requirements.txt
     ```
   - **Collect Data**:
     ```bash
     python cloudmapper.py collect --account ABCD
     ```
     - **Explanation**:
       - `collect`: Gathers metadata about the AWS environment.
       - `--account ABCD`: Specifies the account ne (if available).

4. **AWS ELB**:
   - Identify backend instances by examining the configuration of load balancers in AWS.
   - **Example Command**:
     ```bash
     aws elbv2 describe-target-health --target-group-arn arn:aws:elasticloadbalancing:region:account-id:targetgroup/ABCD/12345678
     ```
     - **Explanation**:
       - `aws elbv2 describe-target-health`: Describes the health of targets in the specified target group.
       - `--target-group-arn arn:aws:elasticloadbalancing:region:account-id:targetgroup/ABCD/12345678`: Specifies the target group ARN.

#### Accessing Internal or Reading Data from Sources Found

1. **Exploiting Publicly Accessible Services**:
   - Once public services or buckets are identified, check for misconfigurations or sensitive data.
   - For Azure:
     - Access public blobs or file shares.
       ```bash
       az storage blob list --container-ne <container_ne> --account-ne <account_ne> --query '[].{ne:ne}'
       ```
   - For AWS:
     - Access public S3 buckets.
       ```bash
       aws s3 ls s3://<bucket_ne>
       ```

2. **SSH into Virtual Machines**:
   - If public IPs and SSH services are identified, attempt to access using known credentials or brute-force techniques.
   - Example (Azure VM):
     ```bash
     ssh user@<public_ip>
     ```
   - Example (AWS EC2):
     ```bash
     ssh -i <key_pair.pem> ec2-user@<public_ip>
     ```

3. **Pivoting to Internal Networks**:
   - Use identified load balancers to understand the internal network structure.
   - Perform further reconnaissance on internal IPs using SSH tunneling or VPN access if credentials are obtained.

By leveraging public information and using cloud-specific reconnaissance tools like Azure CLI, MicroBurst, LAVA, Pacu, and CloudMapper, you can gather details about Orgs's cloud infrastructure and navigate through load balancers to access internal endpoints and potentially sensitive data.