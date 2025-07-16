```
$userne = " Ddagentuser "

$password = ConvertTo-SecureString "Dd4y)arXY7+WmMBK" -AsPlainText -Force

$credential = New-Object System.Management.Automation.PSCredential($userne, $password)

$ips | %{Get-NetSessionloggedon -Credential $credential -Verbose}
```