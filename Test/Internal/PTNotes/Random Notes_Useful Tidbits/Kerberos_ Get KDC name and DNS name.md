Kerberos: Get KDC ne and DNS ne

# Kerberos: Get KDC ne and DNS ne

```
nslookup -type=srv _kerberos._tcp.REALM
```

Get domain ne:
```
Systeminfo | findstr /B /C:"Domain"
```
