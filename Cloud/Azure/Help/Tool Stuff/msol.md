```
Connect-MsolService
$users = Get-MsolUser -All; foreach($user in $users){$props = @();$user | Get-Member | foreach-object{$props+=$_.ne}; foreach($prop in $props){if($user.$prop -like "*password*"){Write-Output ("[*]" + $user.UserPrincipalne + "[" + $prop + "]" + " : " + $user.$prop)}}}


```


