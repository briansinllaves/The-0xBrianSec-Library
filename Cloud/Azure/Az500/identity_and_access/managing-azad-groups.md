
# Managing Az AD Groups

> **Original text preserved**, with expanded notes/commands and Q&A (✅ answers).

---

## Original Notes (Preserved Verbatim)

Managing Static Groups using the GUI
	• 2 types
		○ Ms 365
			§ Has group email address
		○ Security
			§ Do you want Ad roles can be assisned to the group
				□ If no then you can choose memebership type
					® Assigned
					® Dynamic user/device
						◊ Need p1 license
				□ If yes then membership type is assigned
				□ You cant change after group is created
	• Resource role assignment
		○ Resource group
		○ Iam
			§ Add Azure role assignments
			§ We want members to have access to everything in this resource group
				□ Choose contributor
					® Assign access to user,group or sp
					® Members, choose group,
					® Click iam to verify
		○ Look at group > azure role assignments > verify that group with contribitur is there. 



Managing Static Groups using powershell

	• Get-command *az*group*

	• Get-command *azadgroup*
	• 
	• New-AzADGroup -displayname "App2Admins" -mailnickname App2Admins
	• 6346-63463-63463tg3-63s34-64j34
	• Copy group id, sometimes its needed
	• #create an array of similar items
		○ I want to add whats already in the variable
		○ $members = @()  
		○ $members += (get-azaduser -displayname "luke").id
		○ $members
		○ $members += (get-azaduser -displayname "brian").id
		○ $members
		○ 2324r2f-23f23f-23f2-2f235t-43g3
		○ 666d-ds6ds-sds6ds6d-6sd6dsd6-s6
		○ Add-azadgroupmember -targetgroupobjectid 6346-63463-63463tg3-63s34-64j34 -memberobjectid $member
		○ Get-azadgroupmember -groupdisplayname App2Admins

Managing Static Groups using the CLI

	• List all group properties
		○ Az ad group list
	• List specific group
		○ Az ad group list --query [].displayName
	• Create group name
		○ Az ad group create -display-name App3Admins --mail-nickname App3Admins
		○ Check az ad group list
	• User list / Add user to group
		○ As ad user list
		○ Az ad group member add --group App3Admins --member-id 3453f-345-f3-f346
		○ Az ad group list --group App3Admins --query [].displayName
	• Delete Group
		○ Az ad group delete --group App3Admins
		○ Az ad group list --query [].displayName



Working with Dynamic Azure AD user Groups & the gui

	• Must have enterprise+security license
		○ Look at groups
		○ Az ad roles can be assigned to this group-no
		○ Choose membership type- dynamic user
		○ Under Dynamic user members-add dynamic query
			§ Choose a property
				□ City
			§ Operator
				□  equals
			§ Value
				□ Milan
			§ Rule syntax
				□ (user.city -eq "Milan")
			§ Can take up to a day, if you need immediate, manually assign it


Enabling Self-service group management (SSGM)

	• Groups> general
		○ Owners can manage group membership requests in the access panel - yes
	• In groups, select group
	• Edit details > this group requires owner approval OR is open to join for all users
	• If 'requires owner approval', the requestee will be asked for business justification 


Test

You would like to view only Azure AD group names. Which command should you use?


az ad group list --query[].displayName

az ad group list --query [].Name

az ad group list --query [].displayname

az ad group list --query [].displayName

You want to create a static Azure AD group. Which “Membership type” should you choose?


Assigned
Dynamic device
Dynamic user
Azure AD group

You are using the Azure Portal to configure self-service group management. Where should you navigate?

Azure AD/Security/Conditional Access
Azure AD/Users/General
Azure AD/Groups/General
Azure AD/Security/PIM

Which PowerShell cmdlet is used to add members to an Azure AD group?

Add-AzGroup
New-AzADGroup
Add-AzADGroup
Set-AzADGroup

What is required to allow the creation of Azure AD dynamic user groups?

Microsoft Intune
Azure AD Premium P1 license
Global administrator Azure AD role
Contributor RBAC role

---

## Augmented Notes & Commands

### PowerShell
```powershell
New-AzADGroup -DisplayName "App2Admins" -MailNickname "App2Admins"
$gid = (Get-AzADGroup -DisplayName "App2Admins").Id
$uid = (Get-AzADUser -DisplayName "Luke").Id
Add-AzADGroupMember -TargetGroupObjectId $gid -MemberObjectId $uid
Get-AzADGroupMember -GroupDisplayName "App2Admins"
```

### CLI
```bash
az ad group list --query [].displayName
az ad group create --display-name App3Admins --mail-nickname App3Admins
az ad group member add --group App3Admins --member-id <UserObjectId>
```

## Q&A (✅ Correct Answers)
- **View only group names:** `az ad group list --query [].displayName` ✅  
- **Static group membership type:** Assigned ✅  
- **SSGM portal path:** Azure AD/Groups/General ✅  
- **Cmdlet to add members:** Add-AzADGroupMember ✅  
- **Requirement for dynamic groups:** Azure AD Premium P1 license ✅  
