Note: This technique requires the same version / updates as whatever the original was created on (e.g. Microsoft SQL 2016 with SP3). The procedure to restore the master database is different from normal database restores.

Start the database in single user mode (-m option to startup). Connect using sqlcmd (may need to install)

Run the following:

1. restore database master
2. from disk = 'c:\share\master.bak' with replace
3. GO