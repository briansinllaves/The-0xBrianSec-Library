The computer management group policy is local or domain, if on domain, what gpo actually does is at gpcfilesyspath which is on the dc. reg.pol  is stored at that path.



GPO locator

$gpos = Get-DomainGPO -ComputerIdentity "IN-BOMFRRPAWV13" -Server DEGONADIDEGP001.ABCDglb.com  



Please note that this operation may take some time, so try out patience
```
$gpo = Get-DomainGPOLocalGroup -ResolveMembersToSIDs -Domain ABCDglb.com -Server D.ABCDglb.com
``` 

Now you can grep with the group ne  
```
$gpo | Where-Object{ $_.Groupne -match "_Local_Administrator"}
```


SEE ACTUAL GPO

see the Gpo path = gpcfilesyspath:
```
 \\ABCDGLB.COM\sysvol\ABCDGLB.COM\Policies\{c06f}
```

put the path in file explorer on domain-joined host, not the vm


go to machine> scripts>startup
see reg.pol (what the actual gpo does). 
Open in hex editor(look for tools to get output) if files included, scripts or files, look in dirs