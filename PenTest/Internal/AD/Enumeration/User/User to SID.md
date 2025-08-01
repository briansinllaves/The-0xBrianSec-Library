Convert a userne (e.g., "johnson") to a Security Identifier (SID):

```
dsquery user -ne johnson | dsget user -sid
```
