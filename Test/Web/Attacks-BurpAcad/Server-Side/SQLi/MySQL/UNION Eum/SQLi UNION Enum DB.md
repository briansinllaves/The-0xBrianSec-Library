

   try product category filter.
   
	Use Burp Suite to intercept and modify the request that sets the product category filter.

    Determine the number of columns that are being returned by the query and which columns contain text data. 
    Verify that the query is returning two columns, both of which contain text, using a payload like the following in the category parameter:
    'UNION+SELECT+'abc','def'#

    Use the following payload to display the database version:
    'UNION+SELECT+@@version,+NULL#

https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft