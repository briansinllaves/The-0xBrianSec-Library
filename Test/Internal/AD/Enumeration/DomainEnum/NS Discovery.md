
LDAP Records

```
# Query for LDAP SRV records
_ldap._tcp.<domain>

For example: _ldap._tcp.n.ad.pl.com
```


Domain Controllers
```
# Query for Domain Controller SRV records
_ldap._tcp.dc._msdcs.<domain>

```

To find the primary DC:
```
# Query for the primary DC SRV record
_ldap._tcp.pdc._msdcs.<domain>
```

Kerberos Records
```
# Query for Kerberos SRV records
_kerberos._tcp.<domain>
```

SIP Records
```
# Query for SIP TLS SRV records
_sip._tls.<domain>
```


Office 365 Records
```
# Query for Office 365 SIP Federation over TLS SRV record
_sipfederationtls._tcp.<domain>

For example: _sipfederationtls._tcp.n.ad.ABCDinternal.com
```