
# Managing Az AD Users

> **Everything you wrote is preserved verbatim below**, then expanded with senior-operator theory, corrected commands, and Q&A with ✅ marking the correct answers.

---

## Original Notes (Preserved Verbatim)

• In the portal
  ○ Add a user, 
    § Invite a user
    § Add a user
    § Maybe through az connect
  ○ ! Make sure your under the right tenant

In az powershell
  ○ Get-command *az*user*
    § New-AzADSUser -detail
    § $securestringpassword = convertTo-SecureString -String 'pasdfp' -Asplaintest -force
    § New-AzADSUser  -DisplayName "luke" -UserPrincipalName "luke@quick.com" -Password $SecureStringPassword -MailNickname "Lstar"
      □ Get-azaduser | select displayname
    § Update profile property
      □ Get-azaduser -displayname "luke"
      □ $city = "Milan"
      □ $upn = "luke@quixk.com"
      □ Update-azaduser -uporobjectid $upn -city $city

Using CLI
  ○ Az help
  ○ Az find "az ad user"
  ○ Az ad user list
  ○ Az ad user list --query [].displayName     
    § The [] means we have a collection or array, the dot is to separate the object name from the property, propery/attribute name is case sensitive. 
  ○ Az ad user create --display-name "janice" -password "asdf" --user-principal-name janice@quick.com 
  ○ To disable an user account
    § Az ad user update --id janice@quick.com --account-enabled false


+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Create a Guest user using the portal 

  ○ Can add an external guest by inviting guest, can choose role and group for them
    § Add location, useful for many liceneses- recommended
  ○ The should be at url myapplications.microsoft.com
  ○ 

Create Users using bulk import
  ○ For external bulk invite Download template csv


MFA

• Resource authentication can require MFA
• In Mfa settings, the user will show disabled and then will show enforced after the first time used
• Conditional access >  grant > grant access > check 'require mfa' 
  ○ Conditional access could point to a classified system and require mfa. 
• Stops attacks such as
  ○ Keylogger
  ○ Bf pw attacks
  ○ Dictionary pw attacks
  ○ Phising


Enabling mfa for admin accounts

• Users > per-user mfa
  Mfa for admins
  Az ad > security > conditional access | policies,  new policy from template
  Report only mode is good for testing. 


Enabling mfa for Users
•  14 day "grace period" for MFA registration for new users?
•  enforced means they have signed on at least once

Performing mfa
• Az ad> user> mfa
• Az tenant > security > conditional access


You have turned on MFA for an Azure AD user and that user has signed in at least once since MFA was turned on. When viewing the MFA status for that user, what will the MFA status be?
Enforced


What is wrong with the following PowerShell statement?
New-AzADUser -DisplayName "Lucas Brenner" -UserPrincipalName "lbrenner " -Password $SecureStringPassword -MailNickname "LBrenner"

UPN must look like an ip address


How are Azure AD guest users invited to Azure AD?
Email message

Where can MFA be automatically set to apply to admin accounts?
Conditional Access Policy


When creating Azure AD user accounts, what shows up under the “Type” column?
Member


You are using the Azure CLI and would like to list only display names for Azure AD user accounts. Which command should you use?

az ad user list --query [].displayName



Your Azure AD user account is MFA-enabled to use the Microsoft Authenticator app. What will you need to log in?

Smart phone, username, password


What is an example of multifactor authentication?

Username, keyfob

Which type of file format is used for Azure AD bulk user imports?

CSV

---

## Augmented Theory (Senior Operator Notes)
- **Tenant context**: Verify tenant before creating/inviting.
- **UPN** must be `user@verified-domain.tld`; no spaces; domain verified.
- **Guest B2B** invites through portal or Microsoft Graph (PowerShell/REST).
- **Bulk**: Use CSV template, set **Usage location** before license.
- **MFA strategy**: Prefer **Conditional Access**; start in **Report-only**.
- **MFA status**: After first sign-in, shows **Enforced**.
- Security: MFA mitigates brute-force, credential stuffing, phishing.

## Augmented Commands

### PowerShell (Az.Resources)
```powershell
$Password = ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force
New-AzADUser -DisplayName "Luke" -UserPrincipalName "luke@quick.com" `
  -Password $Password -AccountEnabled $true -MailNickname "Lstar"

Update-AzADUser -UPNOrObjectId "luke@quick.com" -City "Milan"
Get-AzADUser | Select DisplayName, UserPrincipalName
Update-AzADUser -UPNOrObjectId "janice@quick.com" -AccountEnabled:$false
```

### Microsoft Graph PowerShell (Guest Invitations)
```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All","User.Invite.All"
New-MgInvitation -InvitedUserEmailAddress "partner@example.com" `
  -InviteRedirectUrl "https://myapplications.microsoft.com" -SendInvitationMessage:$true
```

### Azure CLI
```bash
az find "az ad user"
az ad user list --query [].displayName
az ad user create --display-name "Janice" --password "P@ssw0rd!" \
  --user-principal-name janice@quick.com --force-change-password-next-login true
az ad user update --id janice@quick.com --account-enabled false
```

## Q&A (✅ Correct Answers Marked)
- **MFA status after first sign-in?** → Enforced ✅  
- **PowerShell error in sample?** → Invalid UPN (trailing space + not email-like) ✅  
- **Guest invite method?** → Email message ✅  
- **Auto-apply MFA for admins?** → Conditional Access Policy ✅  
- **Type column shows?** → Member ✅  
- **CLI to show display names?** → `az ad user list --query [].displayName` ✅  
- **MFA with Authenticator needs?** → Smart phone, username, password ✅  
- **Example of MFA?** → Username, keyfob ✅  
- **Bulk import format?** → CSV ✅  
