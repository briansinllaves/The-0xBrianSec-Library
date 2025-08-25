
# Identity and Access – Exercising Governance Principles

> **Everything you wrote is preserved verbatim below**, then expanded with senior-operator theory, commands, and Q&A with ✅ marking the correct answers.

---

## Original Notes (Preserved Verbatim)

1.

Mycompany.omnimicrosoft.com

Mycompany.widgets.com   attach the dns suffix "widgets" is what users/upns are attached to 


Tenants are like east-west, dev, test, you create users and groups- don’t need a sub
Subs can be moved between tenants
Subs are what gives the power to create resources

	• Groups can be static or dynamic
		○ Dynamic is based off attribute
	• Admin Units
		○ Organize users and groups into AU and delegate management of that AU to that admin, which means they can manage those users and groups in that AU
2.

	• If you have 2 tenants and 1 sub you can move the sub to a different dir, but a sub is tied to 1 tenant.
	• A tenant can have multiple subs. 
	• Change directory means change tenant



3.
	• Tenants have their users, groups, apps


4.
	Think of a tenant as a AD domain
	If you move sub from tenant to tenant, Rbac doesn’t follow the movement of a sub from 1 az ad tenant to a different tenant

	Azpwsh
	Connect-azaccount -tenant asff2342352we -usedeviceauthentication


5.
	Managemnt groups help with heiracrhy setup and makes it easier to point policies

6.
	• Resource groups
		○ Groups resources, and can look at cost of all resources for an app.
		○ ??? What is a lock on a resource group??



	7. The heirarchy 
		a. manangemnet group 
			i. Tenant
				1) User/groups
				2) Subscription
					a) Resources
						i) Resource groups
						ii) Creates resources

	Management groups create a way to direct policy to each part of the tree
		○ Manamgent groups are not enabled by default
		○ You can move subscriptiions into different parts or heights of the heirarchy
		○ Can add role assignment to a management group, through group name and IAM
			§ This would apply to all resources under the management group
			§ Role assignment member could be group or user.
		○ Can give iam in subs or resource groups


	8. Managing resource groups
		a. Through resource group, Can move resources (like a vm) to another resource group, region, or sub
			i. Cant do that for many resources through there actual resource overview page, must go through resource management overview
			ii. If you move a resource from a group to another group, the IAM will be stripped away. So any references targeting that resource id with the new resource id will be problematic
	9. AzAD
		a. As ad connect,
			i. Can sync on prem ad domain
			ii. Az domain name needs to be the same as on prem. 
		--- 

