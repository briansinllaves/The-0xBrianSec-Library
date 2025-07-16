
get domain gpo of computer> get report on interesting gpo> check gplink> see restricted group>check members

You have a user and want to find computers where you can login or local admin
    1. Retrieve the GPOs associated with a specific computer.
    2. Generate a GPO report on interesting groups for examination.
    3. Inspect the GPO's "GPLink" attribute.
    4. Examine the Group settings /restricted group within the GPO.
    5. Identify the users or subgroups that are members of the group configured by the GPO on that computer. 
    6. Determine the nesting level (tier) of groups and users within the nested group structure affected by the GPO.
    7. Discover who the local administrators of the computer are based on the GPO settings.
    8. This will give us targets, see if you have creds for a user or user in the group



    
Get Domain gpo for a computer

```

$gpos = Get-DomainGPO -ComputerIdentity "BOM13" -Server DEG.ABCDglb.com  

# !!  check regardless of error 
```






Choose interesting gpos: tier 1, laps, sccm, any admin, rdp


```
$gpos.displayne  
```



GPO Reporting

Look at:
Who made it
Links
Delegation
Comp config

Install Get-GPOReport
Install RSAT Group policy as MS optional feature
Import-Module GroupPolicy
Get-command -module GroupPolicy

```
Get-GPOReport -ne "IN - Local_Administrator_Access" -Server DEGONADIDEGP001.ABCDglb.com -ReportType HTML -Path "C:\Users\briantest\Desktop\example.html"  
```

![[Pasted image 20231031181624.png]]
If a GpLink is not enforced, the associated GPO will apply to the linked OU and all child objects, unless any OU within that tree blocks inheritance.


delegations, who has what permissions on this gpo

![[Pasted image 20231031181943.png]]

Restricted Group - who are admins/ who can login

who are the Doers on the computer

Dig more into Restricted groups, add to local admin group

$members = Get-DomainGroupMember "GLB_AURA_WinAdm_P01" -Recurse

![[Pasted image 20231031185455.png]]



$members = Get-DomainGroupMember "IN_Local_Administrator" -Recurse

ok, only for specific reasons
![[Pasted image 20231031190559.png]]

ok
![[Pasted image 20231031190805.png]]


problematic, he can local admin to computer as a group member of tier 1 as a t2 user.
![[Pasted image 20231031190839.png]]

lets see what we have on prod or add to target list, check if we have creds

what is the laps pw readers ne included in gpo

```
Get-DomainGPO -Server 10.2.8.10 | Where-Object { $_.Displayne -like "*laps*" } | Select-Object Displayne, ne, GPCFileSysPath | Format-List
```

