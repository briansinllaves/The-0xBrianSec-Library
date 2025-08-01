
need admin

    Log in using the admin credentials.
    Browse to the admin panel, promote carlos, and send the POST request to Burp Repeater.
    Open a private/incognito browser window, and log in with the non-admin credentials.
    Attempt to re-promote carlos with the non-admin user by copying that user's session cookie into the existing Burp Repeater request, and observe that the response says "Unauthorized".
    Change the method from POST to POSTX and observe that the response changes to "missing parameter".
    Convert the request to use the GET method by right-clicking and selecting "Change request method".
    Change the userne parameter to your userne and resend the request.

