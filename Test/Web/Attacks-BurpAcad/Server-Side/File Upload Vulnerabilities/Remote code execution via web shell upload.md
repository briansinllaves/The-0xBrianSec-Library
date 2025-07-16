
 While proxying traffic through Burp, log in to your account and notice the option for uploading an avatar image.
 
Upload an arbitrary image, then return to your account page. Notice that a preview of your avatar is now displayed on the page.

In Burp, go to Proxy > HTTP history. Click the filter bar to open the Filter settings dialog. Under Filter by MIME type, enable the Images checkbox, then apply your changes.

In the proxy history, notice that your image was fetched using a GET request to /files/avatars/<YOUR-IMAGE>. Send this request to Burp Repeater.

On your system, create a file called exploit.php, containing a script for fetching the contents of Carlos's secret file. For example:

``` php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

Use the avatar upload function to upload your malicious PHP file. The message in the response confirms that this was uploaded successfully.

In Burp Repeater, change the path of the request to point to your PHP file:


GET /files/avatars/exploit.php HTTP/1.1
