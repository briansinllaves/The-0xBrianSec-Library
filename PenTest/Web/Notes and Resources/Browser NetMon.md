    Open the Developer Tools: Right-click on the webpage and select "Inspect" or press Ctrl+Shift+I (or Cmd+Option+I on macOS) to open the developer tools.

    Go to the Network Tab: In the developer tools, go to the "Network" tab. This tab allows you to view and interact with network requests made by the webpage.

    Reload the Page: If the page is already loaded, refresh it by pressing F5 or clicking the reload button in your browser. This ensures that you capture the network request you want to modify.

    Find the Request: In the Network tab, you should see a list of network requests made by the webpage. Locate the specific request you want to add the bearer token to. This might be an API request or a request to a particular URL.

    Modify the Request Header: Select the request you want to modify, and on the right-hand panel, go to the "Headers" tab. Look for the "Authorization" header, which is where the bearer token should be added.

    Add the Bearer Token: In the "Authorization" header section, select the type (usually "Bearer") and add the token value in the adjacent input field.

    Send the Request: After adding the bearer token, you can either send the request manually by clicking a "Send" button if available, or you can let the page continue its normal operation, and the modified request will be sent when the page performs the action that triggers it.

Please note that this method is for testing and debugging purposes and is not a recommended way to access secured resources in a production environment. In real-world scenarios, bearer tokens are typically obtained through a secure authentication process, such as OAuth 2.0, and then included automatically by the application making the request rather than manually modifying requests in the browser.
