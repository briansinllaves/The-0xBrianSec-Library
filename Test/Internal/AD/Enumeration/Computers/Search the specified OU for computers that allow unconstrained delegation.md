```
 Get-DomainComputer -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -Unconstrained
```

Tactic: If you've gained access to a computer with unconstrained delegation enabled, it allows you to impersonate any domain user, including administrators, and authenticate to services trusted by the user account and any other services as that user.

**![](https://lh7-us.googleusercontent.com/eSedTRFtV-4SVLcC2YLnNX6FDyuwEJR8aTfnzBHxNCpIN66giHqu1TNfkmlVohTZC4s8yhidSuzL87IxBQxYPCdfXbWQCpkAollrQDLAkw6y6UWtV5IeA6TkZYQI0GNh3gcuVHMK3VLi82l1x4KxQPkGrmeY857u)****![](https://lh7-us.googleusercontent.com/FDKHXhpRA6etIDhj5fjy-BAYPzra4_K1L--6rqzhbsNflNjQ1-AxYolEjLJoagpCf6tBQ8Ivrzg7QECLH6fbpKbZKRE8e-upGIJN3sk4BE2Lda8SFoFavBhIMCtOYrUvFux_vt6oZTfiy0JSxur8x_CSAadaCwyj)**