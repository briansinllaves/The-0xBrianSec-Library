## Split
Splits a string based on a delimiter.
Example: Split content from a file by `:` and get the second part:
```powershell
((Get-Content "dt2.txt") -Split ":")[1]
```

## ExpandProperty
Used with `Select-Object` to expand and return the property of an object.
Example: Get the `department` property of AD users whose department starts with "m":
```powershell
Get-ADUser -Filter {department -like 'm*'} -Properties department,memberof | Select-Object -ExpandProperty department
```
