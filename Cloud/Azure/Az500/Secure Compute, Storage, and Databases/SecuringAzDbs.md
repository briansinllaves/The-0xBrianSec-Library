# Deploying Azure SQL

## Creating Azure SQL Database

### Initial Deployment

**Navigation:** `Home → Azure SQL → Create Single Database`

**Database Options:**
- Single database
- Elastic pool/database server (ties to a SQL database)

### Server Configuration

**Authentication Methods:**
- **SQL Authentication** - Traditional username/password
- **Azure AD Authentication** - Integrated with Entra ID
- **Recommended:** Use both SQL and Azure AD auth

**Admin Accounts to Track:**
- **Azure AD Admin** - Set during creation
- **SQL Server Admin** - Username: `sqlserveradmin`

**Environment Settings:**
- **Workload Environment:** Development (affects sizing and costs)
- **Backup Storage:** Locally redundant backup storage

### Networking Configuration

**Connectivity Method:** Public endpoint

**Firewall Rules:**
- **Allow Azure services and resources** to access this server
- **Add current client IP address** for management access

**Connection Policy Options:**
- **Redirect** - Clients establish connections directly to the node hosting the database
- **Proxy** - All connections routed through Azure SQL Database gateway
- **Default** - Redirect for Azure connections, Proxy for external connections

### Security Options

**Available Security Features:**
- **Microsoft Defender for SQL** - Advanced threat protection
- **Transparent Data Encryption (TDE)** - Data at rest encryption (enabled by default)
- **Dynamic Data Masking** - Hide sensitive data from non-privileged users
- **Azure SQL Auditing** - Track database events

**Additional Settings:**
- **Use existing data** - Sample database option
- **Collation** - Database character set and sorting rules

### Post-Deployment Access

**Query Editor Access:**
1. Navigate to `SQL Database → Query Editor`
2. Sign in with SQL or Azure AD credentials
3. Execute queries: `SELECT * FROM SalesLT.Customer`

**Management Options:**
- **Compute + Storage** - Scale resources up/down
- **Replica** button for high availability configuration

---

## Managing SQL Login Credentials

### SQL Server Management Studio (SSMS) Setup

**Connection Configuration:**
- **Server name:** `example.database.windows.net`
- **Authentication:** SQL Server Authentication or Azure Active Directory
- **Login:** Use admin account created during deployment

### Creating SQL Server Logins

**Server-Level Logins:**
1. Connect to server in SSMS
2. Expand **Security** → **Logins**
3. Right-click **Logins** → **New Login**
4. Configure login properties and permissions

**Login Properties:**
- Login name and authentication method
- Default database assignment
- Server role membership
- User mapping to databases

### Creating Database Users

**Database-Level Users:**
1. Expand **Databases** → Select target database
2. Expand **Security** → **Users**
3. Right-click **Users** → **New User**
4. Map user to login or create contained user

**User Types:**
- **SQL user with login** - Maps to server login
- **SQL user without login** - Contained database user
- **Windows user** - For Azure AD integration
- **Azure AD user** - For cloud-based authentication

---

## Configuring Database Authentication

### Authentication Methods

**Azure/Server Login:**
- Server-level authentication
- Managed at SQL Server instance level
- Applies to all databases on the server

**Database Login:**
- Database-specific authentication
- Contained within individual database
- Independent of server-level logins

### Azure AD Integration

**Entra ID Connection:**
- Use Azure AD credentials to connect to SQL databases
- Connect through SSMS with Azure AD authentication
- Supports multi-factor authentication (MFA)

**Azure AD User Access:**
To allow database access to Azure AD users:

1. Connect to SQL Server with Azure AD authentication
2. Use Azure AD - Password authentication method
3. Enter the user principal name (UPN)

**Important:** Must sign in with Azure AD account to manage Azure AD users in database

---

## Managing Azure SQL Settings

### Security Configuration Options

**Available Security Features:**

**Replicas:**
- High availability and disaster recovery
- Read replicas for performance scaling
- Geo-replication across regions

**Synchronization:**
- Data synchronization between databases
- Conflict resolution policies
- Bidirectional data flow

**Azure SQL Auditing:**
- **Storage Account Keys** - Audit log storage configuration
- **Enable Ledger** - Cryptographic proof of data integrity
- **Tamper Detection** - Proof no data tampering has occurred

**Dynamic Data Masking:**
- Hide sensitive data from non-privileged users
- Configure masking rules per column
- Multiple masking functions available

**Microsoft Defender for Cloud:**
- Advanced threat protection
- Vulnerability assessments
- Security recommendations

**Transparent Data Encryption (TDE):**
- **Storage/Data at Rest** encryption
- **Enabled by default** on new databases
- Customer-managed keys supported

### Authentication Configuration

**Mixed Authentication Mode:**
- Support both SQL Server logins and Azure AD logins
- **Don't check "Support Azure AD auth only"** if using mixed mode

**Identity and Access Management (IAM):**
- Role-based access control at resource level
- Managed Identity configuration available

**Backup Configuration:**
- Retention policy settings
- Point-in-time restore capabilities
- Long-term retention options

**Managed Identity:**
Located under `SQL Server → Identity`
- **Use Case:** When SQL needs to grant permissions to other Azure resources
- **System-assigned** or **user-assigned** identity options

---

## Enabling Azure SQL High Availability

### Replica Configuration

**Navigation:** `SQL Server Overview → Data Management → Replicas`

**Replica Properties:**
- Same SQL database on different server (possibly different region)
- **Connection Strings** available for application connectivity
- **Geo-replica** is readable for read-only workloads

### Failover Options

**Forced Failover:**
- Use during region outages
- **Warning:** May cause short connectivity loss
- Primary becomes secondary after failover

**Replication Management:**
- **Stop Replication** - Geo-replica becomes standalone database
- **Monitor Lag** - Track synchronization delay
- **Test Failover** - Validate disaster recovery procedures

### High Availability Features

**Built-in Availability:**
- Automatic backups and point-in-time restore
- Zone-redundant configuration options
- 99.99% SLA for General Purpose tier

---

## Managing SQL Information Protection Policy

### Data Discovery and Classification

**Navigation:** `SQL Database Overview → Security → Data Discovery and Classification`

**Prerequisites:** Must have correct permissions to access classification features

**Information Protection Integration:**
- **SQL Information Protection** - Database-specific policies
- **Microsoft Information Protection** - Organization-wide policies

### Policy Labels

**Classification Categories:**
- **Confidential** - GDPR, Credit Card, Financial, Banking data
- **Sensitivity Levels:** Low, Medium, High
- **Information Types:** Built-in and custom types

### Classification Management

**Adding Classifications:**
1. Review recommended classifications
2. **Add classifications and labels** manually
3. **Accept recommendations** for automated discovery
4. **Review Dashboard** charts for classification overview

**Compliance Benefits:**
- GDPR compliance reporting
- Data governance insights
- Risk assessment capabilities

---

## Configuring SQL Role Access using Portal

### Resource-Level RBAC

**Role Assignment Location:**
- **Not at SQL database level**
- **At SQL Server level** or higher (Resource Group/Subscription)

**Common Roles:**
- **SQL DB Contributor** - Manage databases but not access data
- **SQL Server Contributor** - Manage SQL servers
- **SQL Security Manager** - Manage security policies

**Assignment Process:**
1. Navigate to **Resource Group → Access Control (IAM)**
2. **Add Role Assignment**
3. Select **SQL DB Contributor** role
4. **Assign access to:** User, group, or service principal
5. **Select members** and assign

---

## Configuring SQL Role Access using CLI

### CLI Role Management Commands

**Get Help:**
```bash
az role --help
az role assignment --help
az role assignment create --help
```

### Create Role Assignment

**Assign SQL DB Contributor Role:**
```bash
az role assignment create --role "SQL DB Contributor" --assignee user@test.onmicrosoft.com --resource-group app1
```

**Verification:**
Check `Resource Group app1 → IAM` to see SQL DB Contributor assignment

### List Role Assignments

**Verify Assignment:**
```bash
az role assignment list --resource-group App1
```

**Filter by User:**
```bash
az role assignment list --assignee user@test.onmicrosoft.com --resource-group App1
```

---

## Configuring SQL Role Access using PowerShell

### PowerShell Role Management Commands

**Discover Available Commands:**
```powershell
Get-Command *roleassign*
```

### Role Assignment Operations

**Create New Role Assignment:**
```powershell
New-AzRoleAssignment -SignInName user@test.onmicrosoft.com -RoleDefinitionName "SQL DB Contributor" -ResourceGroupName App1
```

**Get RBAC Roles at Scope:**
```powershell
Get-AzRoleAssignment -SignInName user@test.onmicrosoft.com -ResourceGroupName App1
```

**Remove Role Assignment:**
```powershell
Remove-AzRoleAssignment -SignInName user@test.onmicrosoft.com -RoleDefinitionName "SQL DB Contributor" -ResourceGroupName App1
```

---

## AZ-500 Practice Questions & Answers

### Question Set 1: Deployment and Resources

**Q1: You have a new Azure subscription with no resources deployed. After deploying Azure SQL Database, how many resources will exist?**
- ❌ 3
- ❌ 1
- ✅ **2**
- ❌ 4

*Note: Azure SQL Database deployment creates both the SQL Server and the SQL Database resources*

### Question Set 2: Connectivity Issues

**Q2: You have deployed Azure SQL but are unable to connect to the SQL server from your on-premises laptop computer. Which items should you check?**
- ✅ **Client IP has been added to firewall**
- ❌ Azure AD authentication is enabled
- ✅ **SQL public accessibility is enabled**
- ❌ TDE is enabled

### Question Set 3: Azure AD Integration

**Q3: You are attempting to add Azure AD users to a SQL database but keep getting errors even though the SQL syntax is correct. What is the most probable cause?**
- ❌ Azure AD Connect has not been configured
- ❌ The SQL server is not running
- ❌ SQL TDE has not been configured
- ✅ **You have not signed into SQL with an Azure AD account**

### Question Set 4: SQL Syntax

**Q4: You need to map a SQL Server user to a database. Which SQL syntax should you use?**
- ❌ New-Login
- ✅ **CREATE USER**
- ❌ New-User
- ❌ CREATE LOGIN

### Question Set 5: CLI Role Assignment

**Q5: You need to grant RBAC role permissions for SQL to an Azure AD user using CLI. What is wrong with the following expression?**
```bash
az role assignment create --role "SQL DB Contributor" --user cblackwell@quick24x7testing.info
```
- ❌ The assignment scope has not been specified
- ❌ "SQL DB Contributor" is not a valid role name
- ✅ **"--user" should be "--assignee"**
- ❌ "az role assignment create" should be "az sql role assignment create"

### Question Set 6: Data Classification

**Q6: What is the purpose of a SQL data sensitivity label?**
- ❌ Define the sensitivity level of data stored in a row
- ❌ Define the sensitivity level of data stored in a table
- ✅ **Define the sensitivity level of data stored in a column**
- ❌ Define the sensitivity level of data stored in a database

### Question Set 7: PowerShell RBAC

**Q7: Which PowerShell cmdlet can be used to grant SQL permissions to an Azure AD user?**
- ✅ **New-AzRoleAssignment**
- ❌ Set-AzUser
- ❌ Grant-AzUser
- ❌ Grant-AzRoleAssignment

### Question Set 8: Database Configuration

**Q8: Which SQL configuration allows multiple databases to use the same underlying resource configuration?**
- ❌ TDE
- ❌ DTU
- ❌ Dynamic data masking
- ✅ **Elastic pool**

### Question Set 9: Geo-Replication

**Q9: You are adding an Azure SQL Database replica in a secondary region. SQL has not yet been deployed to the region. Which type of objects will be created in the secondary region upon successful replica configuration?**
- ❌ Azure Key Vault
- ✅ **Azure SQL Database**
- ✅ **Azure SQL Server**
- ❌ Azure Storage Account

---

## Key Takeaways for AZ-500

### Critical Concepts

**Authentication and Authorization:**
- Azure AD authentication requires signing in with Azure AD account to manage Azure AD users
- Mixed authentication mode supports both SQL and Azure AD logins
- RBAC roles are assigned at server or resource group level, not database level

**Security Features:**
- TDE is enabled by default for data at rest encryption
- Dynamic data masking hides sensitive data from non-privileged users
- Microsoft Defender for SQL provides advanced threat protection
- Data classification supports GDPR compliance and governance

**High Availability:**
- Geo-replicas provide disaster recovery and read scaling
- Forced failover may cause brief connectivity interruption
- Stopping replication converts geo-replica to standalone database

**Command Syntax:**
- CLI: Use `--assignee` parameter, not `--user`
- PowerShell: `New-AzRoleAssignment` for creating role assignments
- SQL: `CREATE USER` maps users to databases, `CREATE LOGIN` creates server-level logins

**Network Security:**
- Client IP must be added to firewall for external connections
- Public accessibility must be enabled for internet connections
- Azure services can be allowed through firewall rules

**Resource Deployment:**
- Azure SQL Database deployment creates both SQL Server and Database resources
- Elastic pools allow resource sharing across multiple databases
- Geo-replication creates additional server and database objects in target region