1. In the lab, log in to your own account.
    
2. In Burp, go to the **Proxy > HTTP history** tab and look at the post-login `GET /my-account` request. Observe that your session cookie is a JWT.
    
3. Double-click the payload part of the token to view its decoded JSON form in the Inspector panel. Notice that the `sub` claim contains your userne. Send this request to Burp Repeater.
    
4. In Burp Repeater, change the path to `/admin` and send the request. Observe that the admin panel is only accessible when logged in as the `administrator` user.
    
5. Select the payload of the JWT again. In the Inspector panel, change the value of the `sub` claim from `wiener` to `administrator`, then click **Apply changes**.
    
6. Send the request again. Observe that you have successfully accessed the admin panel.
    
7. In the response, find the URL for deleting Carlos (`/admin/delete?userne=carlos`). Send the request to this endpoint to solve the lab.