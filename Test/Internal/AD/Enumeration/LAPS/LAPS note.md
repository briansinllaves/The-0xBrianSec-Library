Local Administrator Password Solution (LAPS) passwords are stored passwords used by administrators to gain access to local administrator account. LAPS password storage can be identified by querying for ms-MCS-AdmPwdExpirationTime. If the timestamp exists, LAPS is in use for local administrator passwords. Access to ms-MCS-AdmPwd should be restricted to privileged accounts.  

Tactic: Having the LAPS password for a computer allows you to log in to that computer using the local administrator account associated with that password. If we can privilege escalate to a local administrator account with a password, we could dump hashes, download, install, run with more options, and lateral move, etc.

Get-LAPSPasswords will query Active Directory for the hostne, LAPS (local administrator) stored password, and password expiration for each computer account.

Use the LAPSToolkit

```
Get-LAPSPasswords -DomainController <ip_dc> -Credential <domain>\<login> | Format-Table -AutoSize

```

