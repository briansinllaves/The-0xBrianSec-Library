1. Log in using your own credentials. 
2. in HTTP History click on cookie and look at inspector
3. Notice that the post-login `GET /my-account` request contains a session cookie that appears to be URL and Base64-encoded.
4. Use Burp's Inspector panel to study the request in its decoded form. Notice that the cookie is in fact a serialized PHP object. The `admin` attribute contains `b:0`, indicating the boolean value `false`. Send this request to Burp Repeater.
5. In Burp Repeater, use the Inspector to examine the cookie again and change the value of the `admin` attribute to `b:1`. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request.
6. Send the request. Notice that the response now contains a link to the admin panel at `/admin`, indicating that you have accessed the page with admin privileges.
7. Change the path of your request to `/admin` and resend it. Notice that the `/admin` page contains links to delete specific user accounts.
8. Change the path of your request to `/admin/delete?userne=carlos` and send the request to solve the lab.