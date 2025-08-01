```
$userne = " secretagentuser "

$password = ConvertTo-SecureString "DK" -AsPlainText -Force

$credential = New-Object System.Management.Automation.PSCredential($userne, $password)

$ips | %{Get-NetSessionloggedon -Credential $credential -Verbose}
```