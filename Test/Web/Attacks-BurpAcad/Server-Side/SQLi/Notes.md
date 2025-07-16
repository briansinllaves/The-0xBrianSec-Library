add a backtick to the end of a tracking id

https://portswigger.net/web-security/sql-injection/cheat-sheet

Explanation

SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

In some situations, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a denial-of-service attack.



SQL injection examples

There are a wide variety of SQL injection vulnerabilities, attacks, and techniques, which arise in different situations. Some common SQL injection examples include:

    Retrieving hidden data, where you can modify a SQL query to return additional results.
    
    Subverting application logic, where you can change a query to interfere with the application's logic.
    
    UNION attacks, where you can retrieve data from different database tables.
    
    Examining the database, where you can extract information about the version and structure of the database.
    
    Blind SQL injection, where the results of a query you control are not returned in the application's responses.
