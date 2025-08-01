test if product param is reflected back when you change it

1. Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
2. Insert the following external entity definition in between the XML declaration and the `stockCheck` element:
    
```xml
<!DOCTYPE test [ <!ENTITY [xxe](https://portswigger.net/web-security/xxe) SYSTEM "file:///etc/passwd"> ]>
```
3. Replace the `productId` number with a reference to the external entity: `&xxe;`. The response should contain "Invalid product ID:" followed by the contents of the `/etc/passwd` file.