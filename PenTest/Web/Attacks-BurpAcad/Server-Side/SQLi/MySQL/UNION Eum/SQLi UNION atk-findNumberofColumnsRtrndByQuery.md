results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. 

determine the number of columns returned by the query by performing a [SQL injection UNION](https://portswigger.net/web-security/sql-injection/union-attacks) attack that possible returns an additional row containing null values.

1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Modify the `category` parameter, giving it the value. Observe that an error occurs.
```sql
'UNION+SELECT+NULL--
'ORDER+BY+1--
```

4. Modify the `category` parameter to add an additional column containing a null value:
    
    ```sql
 'UNION+SELECT+NULL,+NULL-- 
 'UNION+SELECT+NULL,+NULL,+NULL--   
```
    `
1. Continue adding null values until the error disappears and the response includes additional content containing the null values.

https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns