

after login, open application tab or  curl  command  to get bearer token back in response id'd as access toke
curl --request POST \
  --url https://login.ABCD.com/open/oauth2/access_token \
  --header 'content-type: application/x-www-form-urlencoded' \
  --cookie 'amstg_encrypt=!KPp2kFXx2PydUuA%3D%3D' \
  --data userne=ifs \
  --data password=1c11XO11r1a31tW \
  --data grant_type=password \
  --data client_id=urn:Code-Review-Services \
  --data client_secret=cbXDPXDhZVkhRzKwJdwu \
  --data 'scope=openid email profile' \
  --data auth_chain=oauthServiceAccount

add this to post man collection as bearer token

request > get access token in response > use response access token in header as 


```
Authorization: Bearer asdfasdgv7797dssa
```



pass in burp





or

on chromium logon in burp to login-stg 
burp - turn Intercept on
Go to gif site in chromium
Send 
See intercept, add cookies from sites that have been logged into here and then forward, turn off intercept and check chromium


known curl command with creds and id data returns access token. 

