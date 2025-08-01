
can also add in the filter to check when the pwd was last changed, Older = better.


```
	Get-DomainUser -Properties * | select samaccountne, logoncount

Get-DomainUser -Properties samaccountne

```
