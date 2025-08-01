
# disclosure in error messages
change a parameter like id=1 to id=a and look for server or info leak




++++
# disclosure on debug page

site Map" tab. Right-click on the top-level entry for the lab and select "Engagement tools" > "Find comments".
look for debug information.

request that site, look for server info

++++
# Source code disclosure via backup files

see /robots.txt
go to /backup. read code for db


+++
# Authentication bypass

- In Burp Repeater, browse to `GET /admin`. The response discloses that the admin panel is only accessible if logged in as an administrator, or if requested from a local IP.
- Send the request again, but this time use the `TRACE` method:
    
    `TRACE /admin`
- Study the response. Notice that the `X-Custom-IP-Authorization` header, containing your IP address, was automatically appended to your request. This is used to determine whether or not the request came from the `localhost` IP address.
- Go to "Proxy" > "Options", scroll down to the "Match and Replace" section, and click "Add". Leave the match condition blank, but in the "Replace" field, enter:
    
    `X-Custom-IP-Authorization: 127.0.0.1`
    
    Burp Proxy will now add this header to every request you send.
    
    send it and go to / and admin protal should be availablr
    
# Version Control History
1. Open the lab and browse to `/.git` to reveal the lab's Git version control data.
2. Download a copy of this entire directory. For Linux users, the easiest way to do this is using the command:
    


``` bash
wget -r https://YOUR-LAB-ID.web-security-academy.net/.git/ 
```
or to have some auto help

git-dumper https://[...].web-security-academy.net/.git/ websec
	
    Windows users will need to find an alternative method, or install a UNIX-like environment, such as Cygwin, in order to use this command.
    
3. Explore the downloaded directory using your local Git installation. 
 
 git log


7. Notice that there is a commit with the message `"Remove admin password from config"`.

git show 'commit-id'
1. Look closer at the diff for the changed `admin.conf` file. Notice that the commit replaced the hard-coded admin password with an environment variable `ADMIN_PASSWORD` instead. However, the hard-coded password is still clearly visible in the diff.
2. Go back to the lab and log in to the administrator account using the leaked password.
3. To solve the lab, open the admin interface and delete `carlos`.