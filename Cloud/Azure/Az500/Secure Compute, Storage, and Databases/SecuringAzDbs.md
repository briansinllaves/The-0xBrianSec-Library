Deploying Az SQL

    • Create a db
    • Home|Az SQL> create single db, options include elastic pool/db server, ties to a sql db, create new link, auth method-use both sql and az ad auth., set ad admin, 
        ○ So now you have az admin & sql admin creds to know
        ○ Set Server admin login
            § Username: sqlserveradmin
        ○ Choose workload env: development
        ○ Backup: locally redundant backup storage
    • Networking/RemoteManagement
        ○ Can use ssms to manage it from public.
        ○ Set connectvity method: public
    • FW
        ○ Yes
            § Allow az services and resources to access this server
            § Add current client ip address
        ○ Connection policy
            § Redirect - Clients establish connections directly to the node hosing the db
    • Security
        ○ Can add 'defender for sql'
    • Add. Settings
        ○ Use existing data-Sample
    • Create
    • Home>sql overview >
        ○ To see data, Query editor> sign in
        ○ Select * from salesit.customer
        ○ Compute+storage
        ○ Replica button for HA
     
Managing SQL Login Creds

Setup sql in az
• Allow client ip inbound through firewall
• Add sqladmin role
Create Account In SMSS
    • Server name: example.database.windows.net
    • Login: sqladmin   nmae created in azure
    • On left explorer, db > security > rght click "Logins"
    • 

• Create a user
    • Exapnd "Databases" > Security > right clcik Users > 
    
• 


Configuring DB authentication

Azure/Server login
We can use entra id to connect to az sql dbs, connect az sql to smss
Security>Logins, we can manage logins specific to sql 
The logins apply to the server, 

For db login
Under the db > security > login, 


Allow db access to az user:

This wont work



Connect to sql server> for authentication use Az AD- pw

Put in the user principal


Managing Az SQL Settings


• Security options can include:
    • Replicas
    • Sync
    • Azure SQL Auditing
        ○ Storage account keys
        ○ Enable Ledger cryptographic proof of data integrity
            § Proof no tampering has happened
    • Dynamic data masking
    • Defender for Cloud
    • Transparent data encryption
        ○ Storage/data at rest
        ○ On by default
    
    • If sqlserver logins and az ad logins, don’t check Support AzAD auth only. 
    • IAM
    • Backups, retention policy
    • Sql server | Identity
        ○ Managed ID
            § If you need to grant SQL permissions to other resources
    





Enabling Az SQL High Availability

• Sqlserver overview | data management | replicas
• Go to properties of same sql db different server(maybe in a diff region),
• Connection Strings to connect to db
• GEO- is  the replica - readable
Can choose "Forced failover" due to region outage. Can cause short connectivity loss.
If you stop replication, geo will become a standalone


Managing SQL Information Protection Policy


• SQL db overview|Security| Data Discovery and classification (must have correct perms)
Information Protection


• SQL Information Protection
• Microsoft Information Protection

• Policy labels:
Confidental - GPDR, CC, finance, banking, L,M,H.

• Add a classifications and labels
• Review Dashboard charts



Configuring SQL Role Access using Portal

Give IAM sql admin role:
    • Management
    • Resource group
    • Not at the sql db level, but on server
        ○ Sql db contributor
        ○ Add resource group



Configuring SQL Role Access using CLI

>az role --help
Ø Az role assignment --help
Ø Az role assignment create --help

Create/Delete role assignment
    > Az role assignment create --role "SQL DB Contributor" --assignee user@test.onmicrosoft.com --resource-group app1
    • Check
        ○ Resource group app1 > IAM > see sql db contributor

Verify / List
> az role assignment list --resource-group App1


Configuring SQL Role Access using PwSh

GET-COMMAND *roleassign*

Set new role:

> New-AzRoleAssignment -SignInName user@test.onmicrosoft.com -RoleDefinitionName "SQL DB Contributor" -ResourceGroupName App1

Get RBAC role at that scope
> Get-AzRoleAssignment -SignInName user@test.onmicrosoft.com -ResourceGroupName App1

Delete role assignment
> Remove-AzRoleAssignment -SignInName user@test.onmicrosoft.com -RoleDefinitionName "SQL DB Contributor" -ResourceGroupName App1



TEST


 You have a new Azure subscription with no resources deployed. After deploying Azure SQL Database, how many resources will exist?


3
1
2
4

You have deployed Azure SQL but are unable to connect to the SQL server from your on-premises laptop computer. Which items should you check?

Client IP has been added to firewall
Azure AD authentication is enabled
SQL public accessibility is enabled
TDE is enabled


You are attempting to add Azure AD users to a SQL database but keep getting errors even though the SQL syntax is correct. What is the most probable cause of the problem?

Azure AD Connect has not been configured
The SQL server is not running
SQL TDE has not been configured
You have not signed into SQL with an Azure AD account



You need to map a SQL Server user to a database. Which SQL syntax should you use?

New-Login
CREATE USER
New-User
CREATE LOGIN 


You need to grant RBAC role permissions for SQL to an Azure AD user using the CLI. What is wrong with the following expression?
 
az role assignment create --role "SQL DB Contributor" --user cblackwell@quick24x7testing.info



The assignment scope has not been specified
“SQL DB Contributor” is not a valid role name
“--user” should be “--assignee”
“az role assignment create” should be “az sql role assignment create”



What is the purpose of a SQL data sensitivity label?

Define the sensitivity level of data stored in a row
Define the sensitivity level of data stored in a table
Define the sensitivity level of data stored in a column
Define the sensitivity level of data store in a database


Which PowerShell cmdlet can be used to grant SQL permissions to an Azure AD user?

New-AzRoleAssignment
Set-AzUser
Grant-AzUser
Grant-AzRoleAssignment

Which SQL configuration allows multiple databases to use the same underlying resource configuration?

TDE
DTU
Dynamic data masking
Elastic pool


You are adding an Azure SQL Database replica in a secondary region. SQL has not yet been deployed to the region. Which type of objects will be created in the secondary region upon successful replica configuration?

Azure Key Vault
Azure SQL Database
Azure SQL Server
Azure Storage Account
