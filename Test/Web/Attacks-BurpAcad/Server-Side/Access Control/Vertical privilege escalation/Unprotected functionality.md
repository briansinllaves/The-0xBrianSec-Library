administrative functions might be linked from an administrator's welcome page but not from a user's welcome page. 

a user might simply be able to access the administrative functions by browsing directly to the relevant admin URL.

a website might host sensitive functionality at the following URL:

`https://insecure-website.com/admin`

This might in fact be accessible by any user, not only administrative users who have a link to the functionality in their user interface. 


the administrative URL might be disclosed in other locations, such as the `robots.txt` file:

`https://insecure-website.com/robots.txt`

Even if the URL isn't disclosed anywhere, use a wordlist to brute-force the location of the sensitive functionality.

----
[Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)

 

    Go to the lab and view robots.txt by appending /robots.txt to the lab URL. Notice that the Disallow line discloses the path to the admin panel.
  
	In the URL bar, replace /robots.txt with /administrator-panel to load the admin panel.
    Delete carlos.



---------------------------------------------
sensitive functionality mat not be protected but is concealed by giving it a less predictable URL: users might still discover the obfuscated URL in various ways.

For example, consider an application that hosts administrative functions at the following URL:

`https://insecure-website.com/administrator-panel-yb556`

This might not be directly guessable by an attacker. However, the application might still leak the URL to users. For example, the URL might be disclosed in JavaScript that constructs the user interface based on the user's role:

`<script> var isAdmin = false; if (isAdmin) { ... var adminPanelTag = document.createElement('a'); adminPanelTag.setAttribute('https://insecure-website.com/administrator-panel-yb556'); adminPanelTag.innerText = 'Admin panel'; ... } </script>`

This script adds a link to the user's UI if they are an admin user. However, the script containing the URL is visible to all users regardless of their role.

[Unprotected admin functionality with unpredictable URL](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url)

look in site map for an admin panel