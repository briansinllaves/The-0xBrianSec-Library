	ENABLING STORAGE ACCOUNT BLOB FILE VERSIONING
	• To see if versioning has been enabled, Storage Account>container > data protection| tracking>"enable versioning for blobs"
	
	
	
	MANAGING BLOB SOFT DELETION
	
	• Storage Account>container > data protection| recovery > enable for soft deletion for blobs, how long before purged, 7 days is default, and soft delete containers
	
	
	
	WORKING WITH IMMUTEABLE BLOB STORAGE
	• Blob storage that cant be modified or deleted
	• Create storage account>local rudancy> data protection>enable "enable version-level immutability support" > storage account|container|overview>data protection|access control| manage policy, add in retention, don’t allow mods or deletes, can allow proctive writes to append blocks. These for log files, you keep writing to logs. 
	• Container > add> upload files> failed because of protection, add access policy, add time-based retentention, can have different timebased retention for different blobs. If you lock the time-based you will have to wait before you can mod or delete, the blob or the storage container
	• Legal block, is on individual blob, can t delete blob or file, good for 
	preserving storage evidence

	MANAGING AZURE STORAGE ACCOUNT NETWORK ACCESS
	• Storage accounts | container | networking > firewalls and vnets> 
		○ Enable from all networks, including the internet
		○ Enable from selected vnets and ips
		○ When deploying service accounts, think about:
			§  how are they going to be used
			§ What other services need access to them, where you might deploy vms that run code needing to talk to the storage account. 
	• *Storage accounts are by default open to any network including the internet.
		○ Has 2 access keys
			§ Access to the entire Storage Account
			§ Elect to work with a Shared Access signature at the Storage Account level, to allow restricted access to a subset of items in the StorageAccount, for a specific time frame:ip. A SAS toke a specific blob. 
				□ Blob container>open a blob>generate a SAS, enter in start and expiry and ip.
	• Sas 
		○ is a token that grants access rights to az storage resources. Blobs, files, queues, tables
	• Allowed resource types: service, container, object
	• Allowed perms; rwdLACUProcess, immutable storage, premDel
	• Can be pointed to a specific blob

	
	ENABLLING STORAGE ACCOUNT LIFECYCLE MANAGEMENT
	• You can remove items from a StorageAcct automatically after a certain period of time, security, not having stuff hang around that’s sensitive
	• 
	• Blob
		○ Click into the blob container
			§  right click, manually change tier
				□ Cold- for the less frequent accessed.
				□ Hot, cold, archive
		○ StorageAccount|propeties> Datacycle management> lifecycle management
			§ Add rule, last modified or created, more than 60 days, move to cold/archive storage, think data retention regulations-archive, then delete the blob cersion
				□ Should we appliy to all blobs in your StorageAccount
					® Block blobs, files normal
					® Append blobs, files to be appended to like logs
					® Base blob, snapshots versions
				□ Rehydration is unarchiving the blob, or you cant access the data contents until fully rehydrated. 
				□ Limit blobs with filters,
					® Filter set, inclide prefix, containers/file extenstions.
				


	
	MANAGING STORAGEACCT ACCESS KEYS USING THE GUI
	
	• 2 access keys
		○ Connection string to storage-account, can give to program envs.
		○ If you rotate key 1, curren key2 users can still access.
		○ We should probably be using shared access signtures, instead of tracking keys.
		○ Az storage explorer, lets you manage storage account
			Access keys, blob containers and contents, file shares message queues and stored Tables. 
				□ Use access key, If we need to give devs or techs access to a full storage account, instead of creating azad user for them and setting rbac to limit access, just give them a az Storage access key. 
				□ Shared access sig gives access to a subset
	
	MANAGING SA ACCESS KEYS USING CLI
	
	• List SA keys
		○ In pwsh cli
			§ Az storage account keys list --account-name storeasth334 --resource-group App1 --output table 
	• Renew/Regenerate SA Keys
			§ Az storage account keys renew -g App1 -n storeasth334 --key primary
		
	
	MANAGING SA ACCESS KEYS USING POWERSHELL
	• Get-command *storage*key*
	• List SA keys
		○ Get-AzStorageAccountKey -ResourceGroupName app1 -Name storeasth33
		○ (Get-AzStorageAccountKey -ResourceGroupName app1 -Name storeasth33).value[0]
			§ Or use [1] to get key 2
	• Renew/Regenerate SA Keys
		○ New-AzStorageAccountKey -ResourceGroupName app1 -Name storeasth33 -KeyName key2
		

	MANAGING SA SHARED ACCESS SIGNATURES (SASs)
	• To give restricted access to a Storage Account
	• SA overview, security+networking| shared access sigs, 
	• 
	
	
	
	
	Copy blob service sas url, paste in storage explorer
	
	
	
	
	MANAGING BLOB SHARED ACCESS SIGNATURES
	• In storage account container, click blob, option to generate sas, choose key. 
	• Can limit by ip and time/expiry
	
	
	MANAGING ACCESS TO AZURE TABLES
	• Storage account|data storage | tables
	• Stores key and value pairs
	• Can set up access policies and take the sas and put it in explorer to view
	
	USING AZ STORAGE EXPLORER
	• 
	
	ATTACHING A MANAGED DISK TO A VM
	• Doesn’t have to be running
	• Create datadisk, not os, Create lun 0, premium, 50 gb, save
	• Go to disk in resources, can create a snapshot, can be a disk shared between vms, rdp into machine, start button, "create and format hard disk partitions", initialize GPT, right click on unalloacted volune, new simple volume. 
	• Can create a starting point with another snapshot



TEST

What happens when a blob is deleted and storage account versioning is enabled?

Delete blobs and versions are automatically archived
The blob and its versions are deleted
Blobs cannot be deleted when versioning is enabled
Previous blob versions persist

How is a shared access signature (SAS) different from a storage account access key?

The storage account key can provide time-limited access to a storage account
The SAS can provide access to a subset of storage account objects
The storage account key can provide access to a subset of storage account objects
The SAS can provide time-limited access to a storage account


Which PowerShell expression retrieves the primary key from a storage account?


(Get-AzStorageAccountKey -ResourceGroupName app1 -Name storacct1).Primary[0]

(Get-AzStorageAccountKey -ResourceGroupName app1 -Name storacct1).Primary
(Get-AzStorageAccountKey -ResourceGroupName app1 -Name storacct1).Value[0]
Get-AzStorageAccountKey -ResourceGroupName app1 -Name storacct1.Value[0]



 With Azure Tables, which term is equivalent to a database row for a SQL table entry?

Attribute
Property
Schema
Entity


You need to renew the primary key for a storage account named storacct1. What is missing from the following CLI expression?

az storage account keys renew -g app1 -n storaccteastyhz7762


"az storage account” should be “az storage keys”
The ”--key primary” parameter and value are missing
The specified storage account name is incorrect
The “-g” parameter is invalid


 You would like to implement immutable blob storage and have the option to turn off immutability as needed. Which items must be configured?

Time-based retention
Immutability support must be enabled when during the storage account creation process
Immutability support must be enabled after the storage account is created
Legal hold


Why do storage accounts have two access keys?

Either key can be used while the other is rotated
Both are required when accessing the storage account
Only rotated keys can be used to access the storage account
Each key can be used only within a specific time frame


Which network access options are available when securing storage accounts?

Enabled from private networks
Enabled from all networks
Enabled from public networks
Enabled from selected virtual networks and IP addresses


Storage account lifecycle rules can apply to which blob subtypes?

Base blobs
Block blobs
Snapshots
Append blobs


What is the storage account soft delete default purge interval?


7 days
1 hour
24 hours
3 days

 Which items can be specified when creating a blob shared access signature?

RBAC role
Allow/Deny access
Signing key
Allowed IP addresses

What must technicians do before an attached managed disk can be utilized within the VM operating system?

The disk must be initialized, partitioned and formatted
The disk must only be partitioned
The disk must only be formatted
The disk is automatically mounted


Which types of Azure items can be managed using Storage Explorer?

RDS Databases
Virtual machines
Resource groups
Storage accounts