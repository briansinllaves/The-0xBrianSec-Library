To resolve this issue, follow these steps:
https://curl.se/docs/caextract.html download here

1. Copy the certificate file to a local path, referred to as `{ca-cert-path}`.
2. Obtain the company root CA certificate and save it to a local path, referred to as `{root-cert-path}`.
3. Add the following lines to your bash profile:



```
export SSL_CERT_FILE={root-cert-path}/rootcert.pem  
export AWS_CA_BUNDLE={ca-cert-path}/cacert.pem  
export CURL_CA_BUNDLE={ca-cert-path}/cacert.pem  
```

4. Run the command:


```
cat {root-cert-path}/rootcert.pem >> {ca-cert-path}/cacert.pem  
```