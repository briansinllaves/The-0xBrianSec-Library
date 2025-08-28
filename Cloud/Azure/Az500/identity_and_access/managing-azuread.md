# Managing Azure AD

## Access Reviews

* Require **Azure AD Premium P2**
* Enforce **principle of least privilege** by identifying:

  * Global admins
  * RBAC contributors
  * Group memberships that are no longer required
* Ensure compliance with **data privacy standards**

### Configuration

* Azure AD > Identity Governance > Access Reviews
* Choose scope, reviewers, and recurrence
* Auto-apply results if reviewers don’t respond
* Can remove access if user has **no sign-in for 30 days**

### Analyzing Permissions

* Azure AD > Groups > Access Review
* In new review, all users (excludes service principals)
* Reviewers confirm or remove access
* Require justification from users if needed

---

## Conditional Access Overview

* Created in Azure AD
* Require **Azure AD Premium P1** license
* Apply to users or groups
* Restrict access to apps, devices, or locations
* Require MFA for sign-in

### Policy Templates

* **Secure foundation**

  * Require MFA (admins, all users, Azure management)
  * Secure MFA/SSPR registration
* **Zero Trust**

  * Block legacy auth
  * Require MFA for guest access
* **Remote work**

  * Require MFA for risky sign-ins or high-risk users
* **Protect admin**
* **Emerging threats**

  * Require phishing-resistant MFA for admins

### Policy States

* Report-only (test)
* On
* Off

---

## Configuring Conditional Access

* Need at least **P1**
* Must disable **security defaults**
* Configure:

  * Include/exclude users
  * Apps to secure
  * Sign-in risk (block medium/high)
  * Device platform (e.g., Windows)
  * Client apps (modern auth/browser only)
  * Grant access → Require MFA
* Leave session blank if not needed

---

## Password Lockout

* Azure AD > Security > Authentication > Password Protection
* Change lockout threshold (e.g., 10 → 3)
* Set mode to enforce
* View failures in **Sign-in logs**

---

## Roles

* **Azure RBAC roles** (subscription-level IAM): Owner, Contributor, Reader, service-specific roles
* **Azure AD roles** (directory-level):

  * Global Admin, User Admin, etc.
  * Assigned in **Azure AD > Roles**
  * Global Admin cannot create subscription resources (VMs, storage), only manage AD

---

## App Registration

* Azure AD > Enterprise Applications
* Browse gallery or connect to on-prem app
* Assign users/groups to app
* Global Admin has security/compliance/admin apps included

---

## Privileged Identity Management (PIM)

* Require **Azure AD Premium P2**
* Controls admin access:

  * JIT (Just-in-Time) access
  * Limited duration
  * Approval required
  * MFA required
  * Role activation notifications

### Roles in PIM

* **Eligible**: Assigned but must activate to use
* **Active**: Immediate use, no extra step
* Settings: max eligible time, start/end, permanent if allowed

### Managing PIM

* PIM limits access to time-bound roles
* PIM roles won’t show in normal AD roles view
* User activates role before performing tasks
* Can deactivate when done

---

## Service Principals & Managed Identities

* Provide permissions for scripts or code to access resources
* Prevent storing secrets in code

### Service Principals

* Created automatically when an app is registered
* Represent app instances in tenant
* Assign permissions for apps/scripts to access resources
* Types:

  * Legacy (deprecated)
  * App type
  * Managed Identity

### Managed Identities

* **System-assigned**: Tied to resource lifecycle (deleted with resource)
* **User-assigned**: Independent; can be used by multiple resources

### Working with SPs

* Enterprise Applications view = SPs
* App registration assigns app permissions
* Example: assign storage account access through role assignment

### Working with Managed Identities

* Resource > Identity > enable system-assigned
* Assign RBAC roles (e.g., Storage Blob Data Reader)
* User-assigned MIs are created as separate resources and can be attached to multiple VMs

---

## Test

**Which type of entity is automatically created when an app is registered in Azure AD?**

* Service principal ✅

**You would like custom code running in a single Azure VM to have access to storage accounts in RG APP1. What should you configure?**

* System-assigned managed identity ✅

**You are configuring an Azure AD access review. Which resultant actions are available when setting the “If reviewers don’t respond” setting?**

* Remove access ✅

**To which security principle does conducting an Azure AD access review map?**

* Principle of Least Privilege ✅

**Which Azure AD role gives full access to Azure AD?**

* Global Administrator ✅

**Which type of managed identity is removed automatically when the associated Azure resource is deleted?**

* System-assigned ✅

**You are using the Azure portal and have navigated to Azure AD. How can you create a service principal?**

* Register an app ✅

**Which options are available when configuring Azure AD conditional access policies?**

* Users ✅
* Access controls ✅

**A user, Janice Carter, is locked out at sign-in. Where should you investigate in the Azure portal?**

* Azure AD/Sign-in logs ✅

**What is required before configuring conditional access policies for Azure AD?**

* Azure Active Directory Premium P1 ✅

**How does Privileged Identity Management secure administrative access to Azure?**

* Time-limited admin privileges ✅

**Where to configure Privileged Identity Management in Azure portal?**

* Search for “privileged identity management” ✅
