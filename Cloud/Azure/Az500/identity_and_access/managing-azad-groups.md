# Managing Az AD Groups

## Managing Static Groups using the GUI

* **2 types**

  * **Microsoft 365**

    * Has group email address
  * **Security**

    * Do you want AD roles assigned to the group?

      * If **no**, then you can choose membership type:

        * Assigned
        * Dynamic user/device (requires P1 license)
      * If **yes**, then membership type is **Assigned**
      * You cannot change after the group is created

* **Resource role assignment**

  * Resource group
  * IAM

    * Add Azure role assignments
    * We want members to have access to everything in this resource group

      * Choose **Contributor**
      * Assign access to user, group, or service principal
      * Choose group members
      * Click IAM to verify
  * Look at group > Azure role assignments > verify that group with Contributor is there

---

## Managing Static Groups using PowerShell

* `Get-Command *az*group*`
* `Get-Command *azadgroup*`

```powershell
New-AzADGroup -DisplayName "App2Admins" -MailNickname "App2Admins"

# Group ID sometimes needed
$members = @()
$members += (Get-AzADUser -DisplayName "luke").Id
$members += (Get-AzADUser -DisplayName "brian").Id

Add-AzADGroupMember -TargetGroupObjectId <GroupId> -MemberObjectId $members
Get-AzADGroupMember -GroupDisplayName "App2Admins"
```

---

## Managing Static Groups using the CLI

* **List all group properties**

  ```bash
  az ad group list
  ```

* **List specific group**

  ```bash
  az ad group list --query [].displayName
  ```

* **Create group**

  ```bash
  az ad group create --display-name App3Admins --mail-nickname App3Admins
  az ad group list
  ```

* **User list / Add user to group**

  ```bash
  az ad user list
  az ad group member add --group App3Admins --member-id <UserObjectId>
  az ad group list --group App3Admins --query [].displayName
  ```

* **Delete group**

  ```bash
  az ad group delete --group App3Admins
  az ad group list --query [].displayName
  ```

---

## Working with Dynamic Azure AD User Groups (GUI)

* Must have **Enterprise + Security license**
* Look at groups
* Azure AD roles can be assigned to this group → **No**
* Choose membership type → **Dynamic user**
* Under Dynamic user members → Add dynamic query

  * Property: City
  * Operator: equals
  * Value: Milan
  * Rule syntax: `(user.city -eq "Milan")`
* Can take up to a day; if you need immediate results, manually assign it

---

## Enabling Self-Service Group Management (SSGM)

* Go to **Groups > General**

  * Owners can manage group membership requests in the access panel → Yes
* In groups, select group
* Edit details →

  * This group requires owner approval **OR**
  * Open to join for all users
* If "requires owner approval," the requestor will be asked for business justification

---

## Test

**You would like to view only Azure AD group names. Which command should you use?**

* az ad group list --query\[].displayName
* az ad group list --query \[].Name
* az ad group list --query \[].displayname
* **az ad group list --query \[].displayName** ✅

**You want to create a static Azure AD group. Which “Membership type” should you choose?**

* **Assigned** ✅
* Dynamic device
* Dynamic user
* Azure AD group

**You are using the Azure Portal to configure self-service group management. Where should you navigate?**

* Azure AD/Security/Conditional Access
* Azure AD/Users/General
* **Azure AD/Groups/General** ✅
* Azure AD/Security/PIM

**Which PowerShell cmdlet is used to add members to an Azure AD group?**

* Add-AzGroup
* New-AzADGroup
* **Add-AzADGroupMember** ✅
* Set-AzADGroup

**What is required to allow the creation of Azure AD dynamic user groups?**

* Microsoft Intune
* **Azure AD Premium P1 license** ✅
* Global administrator Azure AD role
* Contributor RBAC role
