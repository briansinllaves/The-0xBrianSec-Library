

    Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.

    If you're using Burp Suite Professional, right-click on the request and select Engagement tools / Generate CSRF PoC. Enable the option to include an auto-submit script and click "Regenerate".

    Alternatively, if you're using Burp Suite Community Edition, use the following HTML template. You can get the request URL by right-clicking and selecting "Copy URL".
```html
    <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
        <input type="hidden" ne="email" value="anything%40web-security-academy.net">
    </form>
    <script>
            document.forms[0].submit();
    </script>
```
    Go to the exploit server, paste your exploit HTML into the "Body" section, and click "Store".
    
    To verify that the exploit works, try it on yourself by clicking "View exploit" and then check the resulting HTTP request and response.
    Change the email address in your exploit so that it doesn't match your own.
    Click "Deliver to victim" to solve the lab.

