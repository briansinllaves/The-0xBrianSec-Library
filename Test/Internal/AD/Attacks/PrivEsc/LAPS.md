
---

**LAPSToolkit**

In this lab, LAPS passwords are readable to all Authenticated Users due to their GenericRead ACL against the computer's MS-Mcs-AdmPwd property.

**Using LAPSToolkit to Retrieve LAPS Passwords**

**Lab Setup:**

Ensure that authenticated users are granted the GenericRead permission on the ms-Mcs-AdmPwd attribute.

**Verify LAPS Configuration with Get-LAPSPasswords**

Use the following PowerShell command to verify that the LAPS is set:

```powershell
Get-LAPSPasswords
```

**PowerShell Command to Add Expiration Value:**

To add the expiration value, use the following command in PowerShell:

```powershell
([datetime]"2023-11-30").ToFileTimeUtc().ToString()
```
