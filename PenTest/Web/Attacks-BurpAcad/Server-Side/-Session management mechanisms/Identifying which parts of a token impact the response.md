Sometimes an application may only inspect certain parts of a token. You can use the Character frobber and Bit flipper payload types in Burp Intruder to modify the value of each character or bit position of a token in turn. This enables you to identify which parts of the token impact the response you receive.

For example, if you modify the value of a character in a session token and your request is still processed in your session, it is likely the character is not used to track your session.

https://portswigger.net/burp/documentation/desktop/testing-workflow/analyzing/opaque-data/parts-of-token

