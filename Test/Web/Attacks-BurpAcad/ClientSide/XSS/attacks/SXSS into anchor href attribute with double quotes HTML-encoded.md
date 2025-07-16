- Post a comment with a random alphanumeric string in the "Website" input, then use Burp Suite to intercept the request and send it to Burp Repeater.
- Make a second request in the browser to view the post and use Burp Suite to intercept the request and send it to Burp Repeater.
- Observe that the random string in the second Repeater tab has been reflected inside an anchor `href` attribute.
```html
                       <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="POLE.POLE">
```
- Repeat the process again but this time replace your input with the following payload to inject a JavaScript URL that calls alert:
    
 ```js
 javascript:alert(1)
```