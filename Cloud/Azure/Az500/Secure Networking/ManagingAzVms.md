
    # ManagingAzVms

    > **Your raw notes are preserved verbatim below**, then expanded with senior-operator theory, validated commands, and Q&A with ✅ marking the correct answers.

    ---
    ## Original Notes (Preserved Verbatim)
    ```
    (Your full ManagingAzVms notes pasted above are preserved in this file.)

ManagingAzVms 
LINUX SSH PUBLIC KEY AUTHENTICATION

Can create when your creating your vm
GENERATING SSH KEY PAIRS
	• Vm overview >  reset pw
	• Putty - ssh keygen
	• Public key stored in vm overview
	• Private key is stored on client.
	• For putty have to convert to ppk.
		○ Ssh-auth. Puttykeygenpair.ppk
CONFIGURING LINUX SSH PUB KEY AUTH
Stored in .ssh/
public
MANAGING VMs THROUGH Az BASTION
Windows vm internal has no public ip
Winserver overview, click connect- choose bastion
Basion enables you to rdp and ssh to vm without exposing a public ip on the vm, directly from the azure portal, without th need of any additional client/agent software. 
you connect with username, auth type password/keyvault password and password. 
ENABLING JIT VM ACCESS
Only give perms for a specific amount of time from a particular location
	• Go to the machine of interest
		○ Configuration, enable JIT (click button)
	• Defender for Cloud > Workload protections > servers> under advanced protect>JIT> Review configured and not configured, config port, ip, and time allowed. 
		○ Requestor, Click server and then choose "request access", toggle, on, my ip, 1 hr. add in request justification, "openports"
	• JIT will dynimcally modify nsg rules to allow for that port in that time. 
ADDING Az VM EXTENSIONS
	• Open virtual machine>settings>extenstions+applications
	• Review status
	• Click extension link for details.
	• Can in/un install extensions from overview
	• Click install, choose extension
	• "Configure Custom Script for Linux Extension"
		○ This will allow you to do a lot of config in the vm
		○ Upload script, allows you to browse a Storage Account
		○ Command: sh who.sh    create/deploy
			§ Make sure script doesn’t require user input
			§ No reboot statements, 98 minutes to run, can only be executed once. 
	• Vm > identity, enable "system assigned", this means you can assign perms to this machine. 
	• Check Storage account overview, IAM> role assignments> see permsions to read storage blob, 
	• Look at Storage account>Contianer>scripts>who.sh, edit
LIMITING VM ACESS USING ROLES
	• Vm overview, IAM, add role assignments
	• Resource group, IAM, add role, set vm perms to the whole resource group
	• Subscription overview, IAM, add role, and it trickles down. 
		○ Search "virtual machine "
		○ Virtual machine contributor
			§ Users group-
			§ Managed id, is if its talking to another app
	• If you delete machine that is "system assigned" be sure to delete that as well, 
	• Userassigned, are associated with resources, not tied to resource lifecycle. 
TEST
	(Questions preserved below in Q&A)
    ```

    ---
    ## Senior‑Level Context & Theory
    - **SSH key auth**: Public key lands in `~/.ssh/authorized_keys` on the VM; private key stays on admin station (`~/.ssh/id_rsa` or `.pem`). PuTTY requires `.ppk` conversion.
- **Bastion**: Requires `AzureBastionSubnet` (/26+). No public IP on VMs; browser-based RDP/SSH; avoids inbound NSG holes.
- **JIT**: Through Defender for Cloud; opens NSG rules just-in-time for specific IP/port/duration; default max commonly 3 hours.
- **VM Extensions**: Lightweight agents (Custom Script, Diagnostics, Dependency agent, etc.). Custom Script is non-interactive and time-bounded.
- **RBAC**: Assign at the narrowest scope that meets ops; RG-level is often the sweet spot for least effort + control.

    ---
    ## Validated Commands – PowerShell
    ```powershell
    # Custom Script Extension (Linux)
Set-AzVMExtension -ResourceGroupName App1 -VMName vm1 -Name "CustomScriptForLinux" -Publisher Microsoft.Azure.Extensions `
  -ExtensionType "CustomScript" -TypeHandlerVersion 2.1 `
  -SettingString '{ "fileUris": ["https://<storage>.blob.core.windows.net/scripts/who.sh"], "commandToExecute": "sh who.sh" }'

# Enable System-Assigned Identity
$vm = Get-AzVM -ResourceGroupName App1 -Name vm1
Update-AzVM -ResourceGroupName App1 -VM $vm -IdentityType SystemAssigned

# List role assignments on a VM
Get-AzRoleAssignment -Scope (Get-AzVM -Name vm1 -ResourceGroupName App1).Id
    ```

    ## Validated Commands – Azure CLI
    ```bash
    # Generate SSH key (OpenSSH)
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -C "admin@contoso"

# Create Bastion (requires AzureBastionSubnet existing)
az network public-ip create -g App1 -n BastionPip --sku Standard
az network bastion create -g App1 -n App1Bastion --public-ip-address BastionPip --vnet-name App1VNet --location eastus

# JIT via CLI
az security jit-policy list -g App1
    ```

    ---
    ## Q&A – AZ‑500 Focus (✅ Correct Answers)
    - **What is the purpose of a Microsoft Azure virtual machine extension?**
  - To provide the VM with access to a key vault
  - ✅ To enable a small software agent in the VM to provide additional functionality
  - To allow VM management through Azure Bastion
  - To allow VM just-in-time (JIT) access
- **What strategy allows management of some, but not all, VMs with the least administrative effort?**
  - ✅ Apply RBAC roles to a resource group
  - Apply RBAC roles to a management group
  - Apply RBAC roles to individual VMs
  - Apply RBAC roles to the entire subscription
- **When configuring VM JIT access, what is the default maximum request time?**
  - 1 hour
  - 30 minutes
  - ✅ 3 hours
  - 15 minutes
- **What is the benefit of managing Azure VMs through Bastion?**
  - VMs do not need a private IP address
  - Linux VMs do not require extensions
  - Windows VMs do not require extensions
  - ✅ VMs do not need a public IP address
- **You configured SSH public key auth for a Linux VM. Where is the public key stored?**
  - On the admin station in ~_rsa
  - ✅ On the Linux server in ~/.ssh/authorized_keys
  - On the Linux server in ~/id_rsa
  - On the admin station in ~/.ssh/authorized_keys
- **On a Linux admin station, where is the private key stored?**
  - ~/.ssh/authorized_keys
  - On the Linux server in ~/id_rsa
  - On the Linux server in ~/.ssh/authorized_keys
  - ✅ ~/.ssh/id_rsa
- **Which type of key is used to decrypt (public-key crypto)?**
  - Public
  - Symmetrical
  - Asymmetrical
  - ✅ Private
