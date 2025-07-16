Bypassing Client-Side Validation

Manually modify requests to bypass client-side controls using Burp Suite.

"Proxy" > "HTTP history" to study requests; 
modify `price` parameter in cart addition requests.        

Send the POST /cart request to Burp Repeater.

Refresh the cart and confirm that the price has changed based on your input.