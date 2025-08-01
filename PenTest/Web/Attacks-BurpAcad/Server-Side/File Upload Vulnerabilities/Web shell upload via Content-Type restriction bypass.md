It attempts to prevent users from uploading unexpected file types, but relies on checking user-controllable input to verify this.

1.  Log in and upload an image as your avatar, then go back to your account page.
2.  In Burp, go to **Proxy > HTTP history** and notice that your image was fetched using a `GET` request to `/files/avatars/<YOUR-IMAGE>`. Send this request to Burp Repeater.
3.  On your system, create a file called `exploit.php`, containing a script for fetching the contents of Carlos's secret. For example:
    
    `<?php echo file_get_contents('/home/carlos/secret'); ?>`
4.  Attempt to upload this script as your avatar. The response indicates that you are only allowed to upload files with the MIME type `image/jpeg` or `image/png`.

6.  In Burp, go back to the proxy history and find the `POST /my-account/avatar` request that was used to submit the exploit file upload. Send this to Burp Repeater.

8.  In Burp Repeater, go to the tab containing the `POST /my-account/avatar` request. In the part of the message body related to your file, change the specified `Content-Type` to `image/jpeg`.

10. Send the request. Observe that the response indicates that your file was successfully uploaded.
11.  Switch to the other Repeater tab containing the `GET /files/avatars/<YOUR-IMAGE>` request. In the path, replace the ne of your image file with `exploit.php` and send the request. Observe that Carlos's secret was returned in the response.
12.  Submit the secret to solve the lab.