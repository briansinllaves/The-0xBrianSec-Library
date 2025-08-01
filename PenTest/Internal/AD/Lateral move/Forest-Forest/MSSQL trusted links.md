MSSQL trust link is across forests, so it can be used as a method of forest to forest lateral movement.

Connect to the mssql DB as jon.snow. He is attached to the “north” and he has access to the essos forest sql db. 

```
mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>
```
