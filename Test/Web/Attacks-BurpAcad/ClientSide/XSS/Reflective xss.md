Reflected cross-site scripting (or XSS) arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.


Look for 

website has a search function which receives the user-supplied search term in a URL parameter

application echoes the supplied search term in the response to this URL

## How to find and test

