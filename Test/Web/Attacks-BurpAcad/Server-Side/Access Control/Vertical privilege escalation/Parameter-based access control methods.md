Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location, such as a hidden field, cookie, or preset query string parameter. 

The application makes subsequent access control decisions based on the submitted value. 

For example:
```html
https://insecure-website.com/login/home.jsp?admin=true 
https://insecure-website.com/login/home.jsp?role=1
```


a user can simply modify the value and gain access to functionality to which they are not authorized, such as administrative functions.

 [User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)

1. Browse to `/admin` and observe that you can't access the admin panel.
2. Browse to the login page.
3. In Burp Proxy, turn interception on and enable response interception in proxy settings
4. Complete and submit the login page, and forward the resulting request in Burp.
5. Look at  POST /login. Observe that the response sets the cookie `Admin=false`.  Send  with a change it to `Admin=true`.
6. Load the admin panel and delete `carlos`. 

GET /admin/delete?userne=carlos 



[User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)

1. Log in using the supplied credentials and access your account page.
2. Use the provided feature to update the email address associated with your account.
3. Observe that the response contains your role ID. POST /my-account/change-email
4. Send the email submission request to Burp Repeater, add `"roleid":2` into the JSON in the request body, and resend it.
5. Observe that the response shows your `roleid` has changed to 2.
7. Browse to `/admin`  page and delete `carlos`. or in repeater send request to /admin. look in response to find how to send delete user. 
