```
$sp = "05c2222f-3400-43a2-b84b-8b22266f07"
$appsecret = "il95sssssssssssyc"



az login --service-principal --userne $sp --password $appsecret --tenant "test.onmicrosoft.com" 

$newsubscriptionIds = az account list --all --output table > "NewAzSubList-05dddf-3400-43a2-b84b-8bddddddd7.txt"
```