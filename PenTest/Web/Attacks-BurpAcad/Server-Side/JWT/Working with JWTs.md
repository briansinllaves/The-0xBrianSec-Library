
https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts

JSON web tokens (JWTs) are a standard format for sending cryptographically signed JSON data between systems. They're commonly used in authentication, session management, and [access control](https://portswigger.net/web-security/access-control) mechanisms. This means that if an attacker can successfully modify a JWT, they may be able to escalate their own privileges or impersonate other users.

You can use Burp Inspector to view and decode JWTs. You can then use the JWT Editor extension to:

1. Generate cryptographic signing keys.
2. Edit the JWT.
3. Resign the token with a valid signature that corresponds to the edited JWT.

## Before you start

Install the [JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd) extension. For more information, see [Installing extensions](https://portswigger.net/burp/documentation/desktop/extensions/installing-extensions).

## Viewing JWTs

## Editing JWTs

## Adding a JWT signing key



eyJ0eXAiOiJKV1QiLCJraWQiOiJiL082T3ZWdjEreStXZ3JINVVpOVdUaW9MdDA9IiwiYWxnIjoibm9uZSJmUS57InN1YiI6IlVTX2lmc19Db2RlX1Jldmlld19TZXJ2aWNlc19TTm93X0F1dG9tYXRpb25fczAwMSIsImN0cyI6Ik9BVVRIMl9TVEFURUxFU1NfR1JBTlQiLCJhdXRoX2xldmVsIjowLCJhdWRpdFRyYWNraW5nSWQiOiI2NzBmNzFmZi1jZWYyLTRiMGEtODk5Zi1iMjFkNGZmYzY2N2UtMzMyMDc5NTYiLCJpc3MiOiJodHRwczovL2xvZ2luLXN0Zy5wd2MuY29tOjQ0My9vcGVuYW0vb2F1dGgyIiwidG9rZW5OYW1lIjoiYWNjZXNzX3Rva2VuIiwidG9rZW5fdHlwZSI6IkJlYXJlciIsImF1dGhHcmFudElkIjoicHU1dXA0QUh5dGp6eEJLZnpnaklZQk9WdzlNIiwiYXVkIjoidXJuOkNvZGUtUmV2aWV3LVNlcnZpY2VzIiwibmJmIjoxNjk1ODQzMzgwLCJncmFudF90eXBlIjoicGFzc3dvcmQiLCJzY29wZSI6WyJvcGVuaWQiLCJwcm9maWxlIiwiZW1haWwiXSwiYXV0aF90aW1lIjoxNjk1ODQzMzgwLCJyZWFsbSI6Ii9wd2MiLCJleHAiOjE2OTU4NDY5ODAsImlhdCI6MTY5NTg0MzM4MCwiZXhwaXJlc19pbiI6MzYwMCwianRpIjoiMG5YUzVsWFhIV2EyZFEzWkhIaDBoZm82eEdZIn0=