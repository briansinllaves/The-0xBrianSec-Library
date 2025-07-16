

after login, open application tab or  curl  command  to get bearer token back in response id'd as access toke
curl --request POST \
  --url https://login-stg.ABCD.com/open/oauth2/access_token \
  --header 'content-type: application/x-www-form-urlencoded' \
  --cookie 'amstg_encrypt=!KPp2kFXDjKdadc6T2sQM%2BCvZTa9gFjxjS6Fy%2BJUNhGPzoZLDJa1CYtRR4rrUY%2FfSZ1iNOFZ5LTJPymEf%2B6ZibNSokJSx6%2BNw53IIxfjjkCUuzPwf2cv5scF; nlbi_1574952=dOuqVDto4C5kIhWp%2FTg3rAAAAAD2pGUUFUYMycI1y%2Bh4NDJp; incap_ses_439_1574952=WMSKBPXDl1%2FBhxv6Q6UXBtrGAWUAAAAAHVA2u5tNNRjgprx2PydUuA%3D%3D' \
  --data userne=US_ifs_Code_Review_Services_SNow_Automation_s001 \
  --data password=1c11XO11Nk1dBr1a31tW \
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

