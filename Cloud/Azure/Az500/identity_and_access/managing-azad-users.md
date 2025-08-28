# Managing Az AD Users

## Portal

* Add a user

  * Invite a user
  * Add a user
  * Maybe through **az connect**
* ⚠️ Make sure you are under the correct tenant

---

## PowerShell

* `Get-Command *az*user*`
* `New-AzADUser`

```powershell
# Create secure password
$SecureStringPassword = ConvertTo-SecureString -String 'P@ssw0rd!' -AsPlainText -Force

# Create new user
New-AzADUser -DisplayName "Luke" -UserPrincipalName "luke@quick.com" `
  -Password $SecureStringPassword -MailNickname "Lstar"

# View users
Get-AzADUser | Select DisplayName

# Update profile property
$city = "Milan"
$upn = "luke@quick.com"
Update-AzADUser -UPNOrObjectId $upn -City $city
```

---

## CLI

* `az help`
* `az find "az ad user"`
* `az ad user list`

```bash
# List users
az ad user list --query [].displayName

# Create user
az ad user create --display-name "Janice" --password "P@ssw0rd!" \
  --user-principal-name janice@quick.com --force-change-password-next-login true

# Disable user
az ad user update --id janice@quick.com --account-enabled false
```

---

## Guest User (Portal)

* Add an external guest by inviting
* Choose role and group for them
* Add location (important for licenses)
* Guest access URL: **[https://myapplications.microsoft.com](https://myapplications.microsoft.com)**

---

## Bulk Import

* For external bulk invite → Download template **CSV**

---

## MFA

* Resource authentication can require MFA
* In MFA settings:

  * User shows **Disabled** initially
  * After first use → **Enforced**
* Conditional Access > Grant > Grant access > Require MFA
* Example: classified system requires MFA
* Mitigates:

  * Keylogger
  * Brute-force password attacks
  * Dictionary attacks
  * Phishing

---

## MFA for Admin Accounts

* Users > Per-user MFA
* Azure AD > Security > Conditional Access → Policies → New policy from template
* **Report-only mode** is useful for testing

---

## MFA for Users

* 14-day grace period for MFA registration for new users
* **Enforced** means user has signed in at least once

---

## Performing MFA

* Azure AD > User > MFA
* Azure Tenant > Security > Conditional Access

---

## Test

**You have turned on MFA for an Azure AD user and that user has signed in at least once since MFA was turned on. What will the MFA status be?**

* Enforced ✅

**What is wrong with the following PowerShell statement?**
`New-AzADUser -DisplayName "Lucas Brenner" -UserPrincipalName "lbrenner " -Password $SecureStringPassword -MailNickname "LBrenner"`

* UPN must be a valid email format (no trailing spaces). ✅

**How are Azure AD guest users invited to Azure AD?**

* Email message ✅

**Where can MFA be automatically set to apply to admin accounts?**

* Conditional Access Policy ✅

**When creating Azure AD user accounts, what shows up under the “Type” column?**

* Member ✅

**You are using the Azure CLI and would like to list only display names for Azure AD user accounts. Which command should you use?**

* `az ad user list --query [].displayName` ✅

**Your Azure AD user account is MFA-enabled to use the Microsoft Authenticator app. What will you need to log in?**

* Smart phone, username, password ✅

**What is an example of multifactor authentication?**

* Username, keyfob ✅

**Which type of file format is used for Azure AD bulk user imports?**

* CSV ✅
