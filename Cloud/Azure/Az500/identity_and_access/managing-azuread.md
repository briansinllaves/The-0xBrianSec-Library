
# Managing Azure AD

> **Original text preserved**, then augmented with theory/commands and Q&A (✅ answers).

---

## Original Notes (Preserved Verbatim)

ReWatch-Managing Azure AD  Az AD Access Reviews
	• Need a P2 license 
		○ Checks unnecessary privs, principle of least priv
			§ Global admin
			§ RBAC contributor
		○ Group membership 
			§ that is no longer needed, user left org, etc
			§ This is still required, user needs to train replacement
		○ Ensure compliance with data privacy standards

Az ad > id governance > access reviews
	• choose what you want to review
	• Scope
	• Specify reviewers
	• Recurrence
	• Can auto apply results to resource, if reviewers don’t respond. 
	• Can choose 'no-sign in for 30 days' actions


Analyzing Permissions using Access Reviews
	• Ad > groups > access review
	• In new access review, all users excludes SPs
		○ Select reviews - Users (they respond to about what they need)
		○ Can select a course of action such as remove access if the reviewer doesn’t respond
		○ Can require an justification explanation for what they need access


Az AD Conditional Access Overview
	• Created in Azure AD 
	• Requires an Azure Premium PI license 
	• Can apply to users or groups 
	• Access for secured apps can be allowed only from admin 
	• secured stations in secured locations 
	• Resource access can be granted or blocked 
	• User MFA sign-in can be required
	• Select a template
		○ Secure foundation
			§ Require mfa
				□ For admins, all users, az management
			§ Securing security info: How users reg for az ad mfa and sspr

		○ Zero trust
			§ Block legacy auth
			§ Require mfa for guest for guest access
		○ Remote work
			§ Require mfa for risky signins/high risk users
		○ Protect admin
		○ Emerging threats
			§ Require phishing resistant mfa for admins
		○ All
	• Can create new policy from scratch
		○ Users
		○ Cloud app or actions
		○ Conditions
		○ Acls 
			§ Grants and sessions
		○ Report-only (for testing), on, off



Configuring Conditional Access Policies
	• Need at least P1
	• When creating a new policy, must turn off secuirty defaults, choose option- my org is using Conditional Access
	• Choose to include or exclude
	• Choose app you want to secure
	• Sign-in risk > configure > choose low and no risk.
	• Medium or high - you don’t want to access
	• Device platформ -windows
	• Client apps- modern auth clients, only choose browser
	• Grant-grant access- require mfa
	• Leave session blank


Configuring Az AD Pw Lockout
	• Az ad > security > auth > password protection
	• Change from 10 > 3
	• Set mode to enforce
	• When lockout is engaged, az ad > monitoring | sign-in logs = failure


Managing Az AD Roles
	• Standard az Sub rbac roles
		○ Sub > IAM > role assignmnet
			§ Any rbac role assigned here will flow down to all of the resource groups in tht sub
				□ Owner, contributor, reader, and some for az services, aks, CDN, storage accounts for blobs and queues
	• AZ ad roles
		○ Az ad > roles
			§ These are different and not rbac roles
			§ Assigning roles
				□ Be in a global admin or able to assign account
				□ Go into user account | assigned roles
				□ Even with global admin, 
					® cant create resources like vms or storages under subscription
					® Can view users and add users in ad



Registering Apps in AzAD
	• AD | Ent applications > browse gallery or azure connect to connect to on prem app, 
	• Click on app, add assignment to let users or groups access the app
	• Gadmin has security, compliance, admin app included


Az AD Privileged Id Management (PIM)
	• Need P2
	• Control limited admin prived ops access
	• JIT admin access
	• Limited time admin access
	• Approval based
	• Requires admin mfa, role activation notifications
	• PIM assignment Can be configured
		○ Eligible roles, is admin but requires justification or action to exercise perms
		○ Active roles, not action by admin is needed, can perform the action as needed
		○ In "Add assignmnet" setting, can set "maximum allowed eligible time" start/end, permananent
		○ Pim user (special admin) activates role and can set duration of time to do the roles task


Managing PIM
	• Used to limit access to resources
	• If you assign a role in ad that role for that user is permanent
		○ If you do it pim his access is limited by time, and requires him to activate
	• The pim role wont show in ad role, check the pim roles. 
	•  The pimed user can deactivate privs when done
	• If they havent waited at least 5 minutes to do something, they will get a failure message
	• They can manage az or ad resources


Security service principals and managed identities
	• These give us a way  to provide permissions to scripts or code running in a vm to access another Az resource, such as needing to read from and storage acct blob. 
	• Manage the the ids in Az, don’t let devs store them in code. OR We want them encrypted. 
		○ Easier to maintain creds if there is a creds change.
	• Service principals - azure ad object
		○ When you register an app in Az ad, it is automatically created for that app. 
			§ You can assign permissions to that app, think of it as being an instance of that app within that az ad tenant
		○ Using the SP you give script, code, or app perms to some other az resouce that it needs access to. 
		○ 3 SP types
			§ Legacy, not used
			§ App type, which is discussed above
			§ Managed id
	• A Managed ID
		○ 2 types
			§ System assigned managed id
				□ If you open the vm properites and look at 'Idenity' and turn it on, it is tied to the lifecycle of the resouce; its deleted with the resource
				□ With the id you give perms to the vm, so anything running in it would have those perms.
			§ User assigned managed id
				□ Not tied to the resource lifecycle, can be associated with multiple resources. 
				□ Home> subs > add role assignmnet, MI, write id name, select a role like 'storage account contributor. 


Working with service principals
	• AD > enterprise applications view, are also are SPs. 
	• Az app registration, is where you give apps perms.
		○ Ex: give an app a SP to access a storage account
		○ Home > subs> IAM> add role assignment- reader access or storage blob data reader
			§ When selecting role assignment, search for app. This will get the perms.
			§ Check in sub > IAM, this will flow down to all storage accounts through the hierachy
			§ Open resources > iam > see app for roles. 



Working with managed identities
	• Resources > identity > system - tied to the lifecycle / user assigned-not tied
	• For system, turn on, it will register with az ad, you will get a obj id and can assign az role assignments. I can sign permissions to other az resources to this vm
	• From the resource perspective
		○ Resouces > IAM > click Add, add role, select Storage blob data Reader, assign access to a ManagedID, select members, choose vm as category, and there is MI, check IAM and storage account to see it

	Create ManagedID as resource
	• Resources > create > type ManagedID in search > select user assigned,  deploy to a sub, resource group, region and give a name, no tags, check: go to resources to see it/ you don’t need both. 
	• Check home or search Managed ID, and objec will appear. Can choose az role assignments and give it a role assignment. Then go to resource and attach it to vm
		○ we can see who gets that privilege, in associated resources view. 

Test

Which type of entity is automatically created when an app is registered in Azure AD

User-assigned managed identity
System-assigned managed identity
Dynamic device group
Service principal

You would like custom code running in a single Azure virtual machine to have access to storage accounts in a resource group named APP1. What should you configure?
Custom RBAC role
Service principal
System-assigned managed identity
User-assigned managed identity


You are configuring an Azure AD access review. Which resultant actions are available when setting the “If reviewers don’t respond” setting?
Approve access
Pause review
Remove review
Remove access


To which security principal does conducting an Azure AD access review map to

Principle of Least Privilege
User sign-in security
OS hardening
RBAC permissions

Which Azure AD role gives full access to Azure AD?


User
Owner
Global Administrator
Contributor

Which type of managed identity is removed automatically when the associated Azure resource is deleted

User-assigned
Dynamic user group
System-assigned
Dynamic device group


You are using the Azure portal and have navigated to Azure AD. How can you create a service principal?

Deploy a new Azure virtual machine
Go to the Service Principals view and click Create
Register an app
Service principals cannot exist in Azure AD



Which options are available when configuring Azure AD conditional access policies?

Dynamic group membership
Access controls
SSO
Users



A user, Janice Carter, complains that upon sign-in she received a message stating that her account is locked out. You would like to investigate further. Where should you navigate to in the Azure portal?


Azure AD/Sign-in logs
Azure AD/Groups
Azure AD/Users
Azure AD/Security


What is required before configuring conditional access policies for Azure AD?


Azure Active Directory Premium P1
Azure Active Directory Premium P2
Microsoft Intune
Global Administrator privileges

How does privileged identity management secure administrative access to Azure?

Time-limited admin privileges
Approvals for admin privilege usage
Requirement for admin SSO
Requirement for admin MFA sign-ins

 You would like to configure privileged identity management in Azure. Where should you navigate to in the Azure portal?

Management groups
Azure AD
Search for “privileged identity management”
Azure subscription

---

## Augmented Theory
- **Access Reviews (P2)** enforce least privilege continuously; auto-removal on non-response.
- **Conditional Access (P1)**: start in Report-only; disable Security defaults first.
- **PIM (P2)**: JIT elevation; approvals; MFA on activation; audit trail.
- **SP vs MI**: SP is app identity; MIs are managed by Azure (system-assigned tied to resource lifecycle).

## Q&A (✅ Correct Answers)
- **Entity auto-created on app registration?** → Service principal ✅  
- **VM code needs access to storage in RG:** → System-assigned managed identity ✅  
- **Access review non-response action:** → Remove access ✅  
- **Principle behind access reviews:** → Principle of Least Privilege ✅  
- **Full Azure AD role:** → Global Administrator ✅  
- **MI removed with resource:** → System-assigned ✅  
- **Create a service principal:** → Register an app ✅  
- **Conditional access options available:** → Users ✅, Access controls ✅  
- **Investigate sign-in lockout:** → Azure AD/Sign-in logs ✅  
- **Requirement before CA policies:** → Azure Active Directory Premium P1 ✅  
- **PIM secures admin by:** → Time-limited admin privileges ✅  
- **Where to configure PIM:** → Search for “privileged identity management” ✅  
