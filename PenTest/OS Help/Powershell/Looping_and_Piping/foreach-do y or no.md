take list of usernes and passwords and run in a script  to scan domain for disabled and active users. - Password assessment

-----------------------------------------------------------------
```
cmd > runas /netonly /user:DOMAIN\user powershell.exe
```

new window (powershell)

```
nslookup domain
import-module powerview recon module or . .\powerview.ps1
$users = Get-Content C:\users\user\downloads\users-REPLACE
$disabled = @()
$current = @()
```


```
foreach ($u in $users)
{
    $i = Get-DomainUser -Domain DOMAIN-REPLACE -Server DOMAIN-IP-REPLACE -Identity $u
    if (-not ([string]::IsNullOrEmpty($i)) -and $i.useraccountcontrol.ToString() -like "*ACCOUNTDISABLE*")
    {
        $disabled += $u
    } else {
        $current += $u
    }
}

```