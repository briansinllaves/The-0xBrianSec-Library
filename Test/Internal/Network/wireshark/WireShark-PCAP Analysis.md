SMB interaction is signed:
```
smb2.flags.signed == 1
```

SMB interaction is not signed:
```
smb2.flags.signed == 0
```

SMB ned Pipe Operations
```
smb2.ned_pipe && (smb2.cmd == 0x25 || smb2.cmd == 0x26)
smb2.cmd == 0x25 (for read requests)
smb2.cmd == 0x26 (for write requests)
```

Extractable SMB objects are GPO:
```
smb2.nt_status == 0x00000000 && smb2.cmd == 0x03 && smb2.filene contains ".pol"
```

Extractable SMB objects, files fly around the network
```
smb2.cmd == 0x06 || smb2.cmd == 0x09
 ```

RPC
```
rpc
```

ned Pipes
```
smb2.pipe_ne
```

LDAP connections are signed:
```
ldap.authmech == "SASL" || ldap.authmech == "GSSAPI" || ldap.authmech == "KRB5"
```


LDAP connections are not signed:
```
ldap.authmech != "SASL" && ldap.authmech != "GSSAPI" && ldap.authmech != "KRB5"
```


HTTP traffic to anywhere
```
http
```


Interesting extractable HTTP object:
```
http.file_data
```

other interesting extractable HTTP objects:
```
http.content_type == "text/html"
```


HTTP Authentication (including NTLM)
```
http.authbasic || http.authbearer || http.authdigest || ntlmssp
```


HTTP traffic to MS services
```
http.host matches "(?i)\\b(microsoft\\.com|msupdate\\.com|windowsupdate\\.com|office365\\.com)\\b"
```


LLMNR requests exist
```
udp.port == 5355
```

DNS queries and responses
```
dns
```


Kerberos traffic::
```
kerberos
```


Active Directory replication
```
dserpc
```


NTLM authentication
```
ntlmssp
```

NTLMv2 hashes
```
ntlmssp.ntlmv2_response
```

netlogon
```
tcp.port == 445 && netlogon
```

