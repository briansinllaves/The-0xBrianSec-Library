The computer management group policy is local or domain, if on domain, what gpo actually does is at gpcfilesyspath which is on the dc. reg.pol  is stored at that path.



GPO locator

$gpos = Get-DomainGPO -ComputerIdentity "IN-BOMFRRPAWV13" -Server DEGONADIDEGP001.ABCDglb.com  



Please note that this operation may take some time, so try out patience
```
$gpo = Get-DomainGPOLocalGroup -ResolveMembersToSIDs -Domain ABCDglb.com -Server DEGONADIDEGP001.ABCDglb.com
``` 

Now you can grep with the group ne  
```
$gpo | Where-Object{ $_.Groupne -match "IN_Local_Administrator"}
```


SEE ACTUAL GPO

see the Gpo path = gpcfilesyspath:
```
 \\ABCDGLB.COM\sysvol\ABCDGLB.COM\Policies\{c04cfa-9543-49c73729726f}
```

put the path in file explorer on domain-joined host, not the vm

![[Pasted image 20231031184946.png]]

go to machine> scripts>startup
see reg.pol (what the actual gpo does). 
Open in hex editor(look for tools to get output) if files included, scripts or files, look in dirs