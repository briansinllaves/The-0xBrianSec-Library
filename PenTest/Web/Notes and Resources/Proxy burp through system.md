System proxy 
Save each on/off
Turn on
Settings>network and internet>proxy
Manual > use a proxy, 127.0.0.1 8080
Don’t use the proxy for local addresses
https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate/ca-cert-chrome-windows
Download cer.der from chromium and add to 
Certmanger> trust root authority
Turn off proxy windows proxy settings
Restart host broswer to set the cert and then went to go to site logged in,  
Turn proxy back on and refreshed page and check burp

Turn off proxy to search web and send request, 
turn on proxy and refresh page to send to burp
Make edits in burp and then turn off proxy to send requests from burp 
 

Go to https://gif.ABCD.com/apps/1013/environments/806/apis/test-breaking-stuffzZGIFAPIZzAYLCkIBQm91O57obGfofz0Vg

Filled in data, turned on proxy and hit execute and it populated at a test api in burp