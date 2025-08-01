Following initial identification of a SQL injection vulnerability, it is generally useful to obtain some information about the database itself.
You can query the version details for the database. The way that this is done depends on the database type, so you can infer the database type from whichever technique works. For example, on Oracle you can execute:

`SELECT * FROM v$version`

You can also determine what database tables exist, and which columns they contain. For example, on most databases you can execute the following query to list the tables:

`SELECT * FROM information_schema.tables`

