

    Log in using the admin credentials.
    Browse to the admin panel, promote carlos, and send the HTTP request to Burp Repeater.
    Open a private/incognito browser window, and log in with the non-admin credentials.
    
    ((Optional)
    Browse to /admin-roles?userne=carlos&action=upgrade and observe that the request is treated as unauthorized due to the absent Referer header.)
    
    Copy the non-admin user's session cookie into the existing Burp Repeater request, change the userne to yours, and replay it.

