    • Accessible via SMB or NFS (mounting)
        ○ You can have both within the same storage account, a single shared folder cant be both at the same time. 
    • Consider the name
        ○ StorageAccountName.file.core.windows.net\sharename
    • Consider the Quota in GB
        ○ Max size it can grow to 
    • Storage tier
    • Placements
        ○ Can run in cloud, on-prem, just needs access through fw. 
    • Needs 445 outbound


Managing File Shares with the Portal
    • Storage Accounts| Data Storage, File share
    • Tier
        ○ Transaction optimized-default-
            § For heavy workloads, great for apps that require file storage as a backend store
        ○ Hot
            § General purpose; team shares, file sync
        ○ Cold
            § Online archive storage
        ○ Can create snapshot and backup policy
        ○ Setup Connection methods
            § Will create a script for you to use depending on os
        

Managing File Shares with CLI
    • Create a new file share, a new shared folder
        ○ Az storage account list --query [].name
        ○ Get keys
            § Az storage account keys list --account-name storaccteast3432 --resource-group App1 --output table
            § $az-storage-accout="sotacct234523"
            § $azstorageaccesskey="/345sert35ser=="
        ○ create a file share
            § Az storage share create --name fileshare1 --account-key $azstorageaccesskey --account-name $az-storage-account       will say true
        ○ Return details on file share
            § Az storage share list --account-key $azstorageaccesskey --account-name $az-storage-account
        ○ Just the name for each share
                □ Az storage share list --account-key $azstorageaccesskey --account-name $az-storage-account --query [].name
        ○ Upload a file to the share
            § Click Upload to load into shell
            § Run Dir -to check
            § Az storage file upload --account-key $Azstorageaccesskey --account-name $az-storage-acct --share-name fileshare1 --source ./Project_A.txt
        ○ Check files in share
            § Az storage file list --account-key $Azstorageaccesskey --account-name $az-storage-acct --share-name fileshare1  --query [].name
            

Managing File Shares with Pwsh
    • Map Drive Letter
    • In vm that you rdp into, paste this in powershell: 
$connectTestResult = Test—NetConnection —ComputerName 
storaccthql.file.core.windows.net —Port 445 
if ($connectTestResu1t. TcpTestSucceeded)  {

    # Save the password 30 the drive will persist on reboot 

cmd.exe /C "cmdkey /add:'"storaccthql.file.core.windows.net'"
/user:'"localh03t\3toraccthq1'"
/pass:'""j5r026G0i971WiEY0hGTOJkEuM3S7wyQNfS9aE2gBzivcwcFp1Km3uXCL313S=='"

    # Mount the drive 

New—PSDrive —Name Z —PSProvider FileSystem —Root "\\storaccthql.file.core.windows.net\budgets" —Persist 

} else {

Write—Error —Message "Unable to reach the Azure storage account via port 445. 
Check to make sure your organization or ISP is not blocking port 445, or use Azure 
P2S VPN, Azure S2S VPN, or Express Route to tunnel SMB traffic over a different 
port. "
}
    • Get-psdrive

    • Create a context pointr
        ○ $ctx=Get-AzStorageAccount -R App1 -Name storacct234f
        ○ $ctx
        ○ $ctx=ctx.context
        ○ $ctx
            § Various endpoints for the different services in the storage account and available within that variable.
    • Create a new file share
        ○ New-AzStorageShare -Name "fileshare2" -Context $ctx
    • Get the new file share
        ○ get-AzStorageShare -Name "fileshare2" -Context $ctx
    • File upload
        ○ Set-AzStorageFileContent -ShareName "fileshare2" -Source "./projectA.txt" -Context $ctx
    • See file in share
        ○ get-AzStoragefile -Name "fileshare2" -Context $ctx
    • Download file to local machine or to cloud shell storage account in portal
        ○ Get-AzStorageFileContent -ShareName "fileshare2" -path "./projectA.txt" -Context $ctx
        ○ Yes to overwrite
    

Mapping a File share with Windows
    • In storage account, connect to smb.


C:\>cmdkey /add:storacct5663.file.core.windows.net /user:Azure\storacct3453 /pass:54j== 

CMDKEY: Credential added successfully. 

C:\>net use Z: \\storeacct44889.file.core.windows.net\projects /persistent:Yes 

Do you want to overwrite the remembered connection? (Y/N) y 

C:\> net use




Mapping a File share with Linux
    

    • Mount point to Azure SMB File Share

 
Sudo mkdir /mnt/budgets             - access this folder to access contents

 
if [ ! —f "/etc/smbcredentials/storaccthql.cred" ]; then

    sudo bash —c 'echo "username—storaccthql" >> /etc/smbcredentials/storaccthql.cred 
    
    sudo bash —c 'echo "password=IWiEYOhGTOJkEuM3S7WYQNfS9aE2g8ZiVCWCFPIKm3uXCL313S40RY/dTeoxtJP==" >> /etc/smbcredentials/storaccthql.cred' 
fi

sudo chmod 600 /etc/smbcredentials/storaccthql.cred

sudo bash —c 'echo "//storaccthql.file.core.windows.net/budgets /mnt/budgets cifs nofail,vers=3.0,credentials=/etc/smbcredentials/storaccthql.cred,dir _mode=0777,file 
Mode=0777,serverino" >> /etc/fstab'
 
sudo mount —t cifs //storaccthql.file.core.windows.net/budgets /mnt/budgets —o 
Vers=3.O,credentials=/etc/smbcredentials/storaccthql.cred,dir_mode=0777,file_mode=0777,serverino


    • To visit mount
$ ls /
Cd /mnt & ls
Cd budgets
Ls
Cd /
Sudo umount /mnt/budgers
Cd /mnt/budgets

    • To see persistance note
    • Sudo tail /etc/fstab
    


TEST

Which TCP port must be open in order to map a drive to an Azure Files shared folder?
3389 
80
445
443

Where are Azure Files shared folders configured in Azure?
Virtual machine
Azure Blueprint
Storage account
Web app

Which CLI command shows files in an Azure Files shared folder?

az storage share list
az storage account list
az storage file list
az storage account keys list


You need to ensure that deleted files in an Azure Files shared folder can be easily recovered by end-users. What should you do?

Enable a storage account time-based retention policy
Enable a storage account legal hold policy
Take shared folder snapshots
Enable storage account versioning


Which Linux command runs commands with elevated permissions?
sudo
Echo
Mkdir
chmod

What is wrong with the following PowerShell expression?


New-AzStorageShare -Name "fileshare2"

Location was not specified
File share names cannot contain numbers
-Context was not specified
File share names must be uppercase

