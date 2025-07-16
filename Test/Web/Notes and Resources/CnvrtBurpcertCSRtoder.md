csr is in the response after generation.
its in pem format

![[Pasted image 20240708150057.png]]

put into pem format
![[Pasted image 20240708150158.png]]

Convert pem to der
```
linux
openssl x509 -inform PEM -in certificate.pem -outform DER -out certificate.der

```

enroll cert and check 

certutil in windows
```
 certutil.exe -dump .\certificate.der
```

![[Pasted image 20240708150417.png]]
