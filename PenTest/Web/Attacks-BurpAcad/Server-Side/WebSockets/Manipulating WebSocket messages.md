1. Click "Live chat" and send a chat message.
2. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message.
3. Using the browser, send a new message containing a `<` character.
4. In Burp Proxy, find the corresponding WebSocket message and observe that the `<` has been HTML-encoded by the client before sending.

{"message":"look at the &lt;"}

1. Ensure that Burp Proxy is configured to intercept WebSocket messages, then send another chat message.
2. Edit the intercepted chat message you sent to contain the following payload:
    
   `{"message":"<img src=1 onerror='alert(1)'>"}`
7. Observe that an alert is triggered in the browser. This will also happen in the support agent's browser.