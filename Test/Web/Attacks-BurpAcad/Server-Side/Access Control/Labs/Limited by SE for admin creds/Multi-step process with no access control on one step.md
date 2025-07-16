1. Log in using the admin credentials.
2. Browse to the admin panel, promote `carlos`, and send the confirmation POST request to Burp Repeater.
3. Open a private/incognito browser window, and log in with the non-admin credentials.
4. Copy the non-admin user's session cookie into the existing Repeater request, change the userne to yours, and replay it.