- **LDAP queries:** Use tools like `ldapsearch` or `BloodHound` with `SharpHound` to enumerate AD objects.

See notes in drive for ldap queries

```
sharphound.exe -c All
```


- **Net Commands:** `net user /domain`, `net group "Domain Admins" /domain` can still be used to gather user and group information.

- **DNS Recon:** `nslookup`, `dig`, or `host` commands to find DNS records (like SRV records for domain controllers).

- **Nmap with NSE scripts:** Use `nmap` scripts such as `ldap-search` or `smb-enum-shares` to gather information about shares or AD.