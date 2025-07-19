ConvertTo-SID and ConvertFrom-SID:
```
# Converting a userne to SID
$SID = ConvertTo-SID -Userne "domain\userne"

# Converting a SID to userne
$Userne = ConvertFrom-SID -SID $SID

```
