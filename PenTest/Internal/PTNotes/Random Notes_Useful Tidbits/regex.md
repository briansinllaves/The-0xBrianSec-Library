
```
sas|password|url|uri|SPN|SVC|pwd|admin|adm|sv|root|service|key|token|userne|keyFile(?<![a-zA-Z2-7])[a-zA-Z2-7]{52}(?![a-zA-Z2-7])|:[A-Za-z0-9+/]{68,70}={0,2}

[`"']{1}((?i)\bBasic |Bearer \b)(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})
` characters are for powershell escaping quotes, if you use other tools, remove them
```

For robustly finding PATS in docs  
```
(?<![a-zA-Z2-7])[a-zA-Z2-7]{52}(?![a-zA-Z2-7])
```


For finding B64 encoded pats using basic auth:  
```
:[A-Za-z0-9+/]{68,70}={0,2}
```

hashicorp tokens

```
hvs\.[A-Za-z0-9_.]{107}
```
https://gchq.github.io/CyberChef/#recipe=To_Base64('A-Za-z0-9%2B/%3D')&input=cHp3aG95cG41eDZ2eXFudG5rbGRoc3VzbGJseGl3enJ2d2Z1dnRsdnRnbmFsbmJ1eHhlZQ


https://regex-generator.olafneumann.org/?sampleText=2020-03-12T13%3A34%3A56.123Z%20INFO%20%20%5Borg.example.Class%5D%3A%20This%20is%20a%20%23simple%20%23logline%20containing%20a%20%27value%27.&flags=i

https://regex101.com/
