1. Determine the user's group membership.
2. Identify the Group Policy Object (GPO) applied to the user's group.
3. Check the GPO link on the Organizational Unit (OU).
4. Retrieve a list of computers within that OU.

When dealing with a user who may have the necessary group permissions to log in, follow these steps to locate the computers that grant access

Start by collecting all GPOs that make changes to local groups. 

This process involves gathering all GPOs across the entire domain and parsing their policy files from the Domain Controller. 

Please note that this operation may take some time, so try out patience

```
Import-Module GroupPolicy

$gpo = Get-DomainGPOLocalGroup -ResolveMembersToSIDs -Domain ABCDglb.com -Server DE001.ABCDglb.com
``` 

OUTPUT
```
GPODisplayne : *- Computer Quarantine
GPOne        : {33C45CAD-130E-42D1-8BC3-730AC6F9B6D1}
GPOPath        : \\ABCDglb.com\sysvol\ABCDglb.com\Policies\{33C45CAD-130E-42D1-8BC3-730AC6F9B6D1}
GPOType        : RestrictedGroups
Filters        :
Groupne      : BUILTIN\Administrators
GroupSID       : S-1-5-32-544
GroupMemberOf  : {}
GroupMembers   : {S-1-5-21-1938565351-2647537887-2759924446-1112}
```




Now you can grep with the group ne  
```
$gpo | Where-Object{ $_.Groupne -match "IN_Local_Administrator"}
``` 
Output:
```
GPODisplayne : IN - Local_Administrator_Access
GPOne        : {9C281DA2-3D08-48FD-92C2-53AA12D62E3B}
GPOPath        : \\ABCDGLB.COM\sysvol\ABCDGLB.COM\Policies\{9c281da2-3d08-48fd-92c2-53aa12d62e3b}
GPOType        : RestrictedGroups
Filters        :
Groupne      : ABCDGLB\IN_Local_Administrator
GroupSID       : S-1-5-21-1938565351-2647537887-2759924446-941825
GroupMemberOf  : {S-1-5-32-544}
GroupMembers   : {}
```


Find OUs that have linked that GPO (Note that you must use the GPOne for the query):

```
Get-DomainOU -GPLink "9C281DA2-3D08-48FD-92C2-53AA12D62E37"
```

output:  

```
usncreated            : 12490952
distinguishedne     : OU=Servers,OU=Tier 1,OU=IN,OU=Territories,DC=ABCDglb,DC=com
ne                  : Servers
gplink                : [LDAP://cn={3f8df701-d165-4c6f-99e8-c6550feebb4c},cn=policies,cn=system,dc=ABCDglb,dc=com;0][LDAP://cn={9c281da2-3d08-48fd-92c2-53aa12d62e3b},cn=policies,cn=system,dc=ABCDglb,dc=com;0]cn=policies,cn=system,dc=ABCDglb,dc=com;0][LDAP://cn={e5fd75e1-cf45-473e-9359-9e14402450f9},cn=policies,cn=system,dc=ABCDglb,dc=com;0]
whenchanged           : 7/10/2023 11:15:29 AM
objectclass           : {top, organizationalUnit}
usnchanged            : 1566114957
dscorepropagationdata : {11/1/2023 9:20:45 AM, 9/15/2023 3:28:42 PM, 6/22/2023 7:28:46 PM, 5/3/2023 9:06:11 PM...}
managedby             : CN=Domain Admins,CN=Users,DC=ABCDglb,DC=com
ou                    : Servers
whencreated           : 1/23/2019 1:03:45 AM
instancetype          : 4
objectguid            : 70b11401-b012-4c85-bbd2-00b242afde4e
objectcategory        : CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=ABCDglb,DC=com
```

Now get all computers of that OU (Use the distinguishedne from the previous output):

```
$comps = Get-DomainComputer -SearchBase ""[LDAP://OU](ldap://OU)=Servers,OU=Tier 1,OU=IN,OU=Territories,DC=ABCDglb,DC=com"
```

output
```
$comps.count 
477
```




