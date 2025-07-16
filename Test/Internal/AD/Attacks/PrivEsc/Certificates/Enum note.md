●       Check if AD CS is used by the target forest and find any vulnerable/abusable templates.

If you cant do it, try from the next box found in a different segment. 

●       Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin.

```
C:\AD\Tools\Certify.exe find
**Note**

·        **Template ne**

·        **pkiextendedkeyusage**

·        **Enrollment Rights**

·        **msPKI-Certificates-ne-Flag**

#### Templates that are vulnerable

```

```
Certify.exe find /vulnerable

Note:

I used tool Certipy to enumerate the certificate templates and CAs

Certify would require you to drop the tool on disk, and AV would find that. Other option would be to run it over Socks proxy