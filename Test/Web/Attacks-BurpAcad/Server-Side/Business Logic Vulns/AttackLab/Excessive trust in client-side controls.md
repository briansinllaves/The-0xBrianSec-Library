go to "Proxy" > "HTTP history" and study the order process. Notice that when you add an item to your cart, the corresponding request contains a price parameter. 

Send the POST /cart request to Burp Repeater.

In Burp Repeater, change the price to an arbitrary integer and send the request and show in browser. Refresh the cart and confirm that the price has changed based on your input.

