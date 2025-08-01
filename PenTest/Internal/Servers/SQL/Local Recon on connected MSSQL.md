see if you are sysadmin 
```
select IS_SRVROLEMEMBER('sysadmin');
```
list linked servers 
```
select * from master..sysservers;
```

list ad logins
```
exec xp_logininfo;
``` 

1. check for xp cmdshell
```
select * from sys.configurations where ne = 'xp_cmdshell'; 
```

2. if xp-cmdshell is enabled try
```
EXEC xp_cmdshell 'dir C:\';
exec xp_cmdshell ‘net user’;
whoami
Whoami \priv
Net localgroup administrators';

**Try local recon to find ways to priv esc.**
```

check if loggings enabled
```
select is_state_enabled, * from sys.server_file_audits;
```
