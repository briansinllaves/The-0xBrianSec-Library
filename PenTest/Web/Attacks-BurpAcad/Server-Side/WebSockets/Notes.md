initiated over HTTP and provide long-lived connections with asynchronous communication in both directions.

- [Intercept and modify WebSocket messages.](https://portswigger.net/web-security/websockets#intercepting-and-modifying-websocket-messages)
- [Replay and generate new WebSocket messages.](https://portswigger.net/web-security/websockets#replaying-and-generating-new-websocket-messages)
- [Manipulate WebSocket connections.](https://portswigger.net/web-security/websockets#manipulating-websocket-connections)


## security vulnerabilities

- User-supplied input transmitted to the server might be processed in unsafe ways, leading to vulnerabilities such as [SQL injection](https://portswigger.net/web-security/sql-injection) or XML external entity injection.
- Some blind vulnerabilities reached via WebSockets might only be detectable using [out-of-band (OAST) techniques](https://portswigger.net/blog/oast-out-of-band-application-security-testing).
- If attacker-controlled data is transmitted via WebSockets to other application users, then it might lead to [XSS](https://portswigger.net/web-security/cross-site-scripting) or other client-side vulnerabilities.