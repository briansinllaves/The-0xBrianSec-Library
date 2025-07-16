connecting to a SQL Server with Windows authentication and specified credentials.


```
proxychains4 -q python3 /home/user/Tools/impacket/examples/mssqlclient.py aev.local/bhtheuser:NotMyRealPasswordMaybe?@10.2.2.4 -windows-auth -file /home/user/sql_cmd.txt

```

