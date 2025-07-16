
Install-Module -ne PowerUpSQL

**Verify SQL Connections:**

  Get SQL Instances
  ```powershell
powerupsql

$instances = Get-SQLInstanceDomain -Verbose -DomainController 1.q.q.14 
```


**Nmap Scan a list of SQL Instance hostnes.** 

```

nmap -vv -n -Pn -sT -T2 --max-rtt-timeout 500ms --max-retries 1 -p"3306,1443,14430-5,51083" -iL .\domain.txt --open -oA nmap_t2reachable

```

**SQL connections**
Checks SQL connections on a specified Domain Controller, providing verbose output with 15 threads.
```
$instances | Get-SQLConnectionTestThreaded -Verbose -Threads 15 > sqlinstanceconnections.txt
```


