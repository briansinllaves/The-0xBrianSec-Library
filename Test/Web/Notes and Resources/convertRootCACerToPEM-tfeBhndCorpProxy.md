you can use the OpenSSL command-line tool. Here's how you can do it:

1. Open a terminal in Kali Linux.
    
2. Navigate to the directory where the root CA certificate file (in .cer format) is located.
    
3. Run the following command to convert the .cer file to .pem format:
    
    TEXTCopy code
    
    ```
    openssl x509 -inform der -in <root-ca-file.cer> -out <root-ca-file.pem>  
    ```
    
    Replace `**<root-ca-file.cer>**` with the ne of your root CA certificate file in .cer format, and `**<root-ca-file.pem>**` with the desired ne for the converted .pem file.
    
4. After running the command, you should now have the root CA certificate in .pem format.
    

You can then use the converted .pem file as `**{root-cert-path}/rootcert.pem**` in the steps mentioned earlier to configure Terraform behind the corporate proxy.