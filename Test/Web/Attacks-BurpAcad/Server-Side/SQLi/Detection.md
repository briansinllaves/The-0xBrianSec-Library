- 
```
- Submitting the single quote character '  and looking for errors or other anomalies.
	
- adding a ' in user ne form
- submit a "number" + <space> to break out.

```
	
- Submitting some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and looking for systematic differences in the resulting application responses.
- Submitting Boolean conditions such as `OR 1=1` and `OR 1=2`, and looking for differences in the application's responses.
- Submitting payloads designed to trigger time delays when executed within a SQL query, and looking for differences in the time taken to respond.
- Submitting OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitoring for any resulting interactions.

- Here's an example of how the given URL with the "sqlquery" parameter can be properly sanitized:

|Original URL|Sanitized URL|
|---|---|
|`https://ABCD-talentlink-west-api-stage1.ABCDinternal.com/IWRetainWeb/IWISAPIRedirect.dll/rest/table/ODFBKG?sqlquery={"filter":{"and":[{"table":"BKG","field":"BKG_EXT_SOURCEID","operator":"like","value":"%TIME%"},{"table":"BKG","field":"BKG_START","operator":">=","value":"' + $fromDate +'"},{"table":"BKG","field":"BKG_END","operator":"<=","value":"' + $toDate +'"}]}}'`|`https://ABCD-talentlink-west-api-stage1.ABCDinternal.com/IWRetainWeb/IWISAPIRedirect.dll/rest/table/ODFBKG?sqlquery=%7B%22filter%22%3A%7B%22and%22%3A%5B%7B%22table%22%3A%22BKG%22%2C%22field%22%3A%22BKG_EXT_SOURCEID%22%2C%22operator%22%3A%22like%22%2C%22value%22%3A%22%25TIME%25%22%7D%2C%7B%22table%22%3A%22BKG%22%2C%22field%22%3A%22BKG_START%22%2C%22operator%22%3A%22%3E%3D%22%2C%22value%22%3A%22%27%20%2B%20%24fromDate%20%2B%27%22%7D%2C%7B%22table%22%3A%22BKG%22%2C%22field%22%3A%22BKG_END%22%2C%22operator%22%3A%22%3C%3D%22%2C%22value%22%3A%22%27%20%2B%20%24toDate%20%2B%27%22%7D%5D%7D%7D`|

In the sanitized URL, the "sqlquery" parameter value has been URL-encoded to ensure that special characters are properly represented. This prevents any potential SQL injection attacks by treating the parameter value as plain text rather than executable SQL code.

Treating the value as plain text rather than executable SQL code is important for security reasons. Here are a few reasons why:

1. Protection against SQL injection attacks: By treating the value as plain text, any malicious SQL code injected by attackers will not be executed by the database. This prevents unauthorized access, data manipulation, or other malicious activities.
    
2. Data integrity: Treating the value as plain text ensures that the data being passed as a parameter is not modified or interpreted as SQL code. This helps maintain the integrity of the data and prevents unintended changes or corruption.
    
3. Compatibility and portability: By treating the value as plain text, the URL can be safely used across different database systems or platforms without worrying about SQL syntax compatibility issues. It ensures that the URL can be executed consistently regardless of the underlying database technology.
    
4. Ease of maintenance: Treating the value as plain text simplifies the maintenance and management of the URL. It eliminates the need for complex SQL code manipulation or validation, making it easier to understand, update, and troubleshoot.
    

Overall, treating the value as plain text mitigates the risk of SQL injection attacks, ensures data integrity, improves compatibility, and simplifies maintenance, all of which contribute to a more secure and robust application.