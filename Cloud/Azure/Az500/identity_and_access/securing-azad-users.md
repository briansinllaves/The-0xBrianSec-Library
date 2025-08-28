# Securing Az AD Users – Authentication, Authorization and Identity Federation

## Federation

* Apps trust the **Identity Provider (IdP)** instead of authenticating directly
* IdP provides a metadata XML file with its public key
* Used for SAML/SSO scenarios

---

## Identity Protection

* **Blade:** Security > Identity protection
* Licensing: **Azure AD Premium P2** (Enterprise Mobility + Security trial possible)

### Policies

* **User Risk Policy**

  * Define users, sign-in risk, controls (block/allow)
* **Sign-in Risk Policy**

  * Define users, risk level, block/allow
* **MFA Registration Policy**

  * Require MFA registration for targeted users

### Reports

* **Risky users** → risk state, level
* **Risky workload identities** → service principals, app IDs
* **Risky sign-ins** → date, user, IP, location, state
* **Risk detections** → detection time, user, IP, type, state

---

## Passwordless Authentication

* Authenticator prompts registration when attempting login
* User adds work account by scanning QR code
* Enable in **Azure AD Tenant > Authentication methods > Microsoft Authenticator settings**
* Set mode = **Passwordless**

---

## Password Protection

* Enforce secure password policies
* Azure AD Tenant > Security > Authentication methods > Password protection

  * Lockout threshold (default 10)
  * Lockout duration (60 sec default)
  * Custom banned password list
  * Extend to on-prem DCs via agent
  * Modes: Audit or Enforced

---

## Azure AD SSO

* Works with Azure AD gallery apps (thousands of prebuilt templates)
* Can configure on-prem apps with password SSO via application proxy
* Users access apps via **[https://myapplications.microsoft.com](https://myapplications.microsoft.com)**
* App SSO configuration:

  * Azure AD > Apps > All Apps > App > Manage > SSO
  * Define attributes (user details) and claims
  * Common: **SAML**
  * Download certificates to trust Azure AD as IdP
  * Always test configuration

---

## Entra Admin Center

* Azure AD > Identity Governance

  * **Entitlement management**: manage external partners/contractors
  * **External IDs & IdPs**

* Protect & Secure

  * Conditional Access
  * Identity Protection
  * Authentication methods
  * Password reset

---

## Self-Service Password Reset (SSPR)

* Azure AD > Security > Authentication methods > Policies
* Options: Passwordless, Push, Any, Email OTP (including external users)
* Azure AD > User > Password reset

  * Default = None
  * Admins always enabled for SSPR (must use 2 methods)

---

## Q\&A

**Which configuration options are available in the Microsoft Entra Admin Center?**

* Groups ✅
* Identity Governance ✅

**Which are common SSO standards?**

* SAML ✅
* OpenID ✅

**Which benefit is realized by configuring user SSPR?**

* Less burden on the help desk ✅

**Which item is related to configuring Password Protection?**

* Lockout threshold ✅

**You need to ensure assistant cloud technicians have access to view storage accounts for a specific resource group only. Which type of access control should you configure?**

* RBAC ✅

**Users complain that after Passwordless Login has been configured, they are still prompted for their password. What is the problem?**

* Users should click “Use an app instead” ✅
