 it is indeed possible to reset the password for a disabled account without re-enabling the account. Here’s how you can do it:
```
Enable-ADAccount -Identity 'hodor'
Disable-ADAccount -Identity 'hodor'
# Import the Active Directory module if necessary
Import-Module ActiveDirectory

# Get the user object for "hodor" and select the Enabled property
$user = Get-ADUser -Identity hodor -Properties Enabled

# Output the status of the Enabled property
$user.Enabled

```

![[Pasted image 20231102001057.png]]


![[Pasted image 20231102001442.png]]

Enabled to verify if password was changed

![[Pasted image 20231102010649.png]]

```
[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Get-Credential -Credential 'hodor').Password))

```
Get-Cred hodor prompts me for the password
the display is the changed password, converts securestring to binary, and the ptrtostringauto converts bitstr to regular

And the account disabled shows the password has been changed 

![[Pasted image 20231102011541.png]]