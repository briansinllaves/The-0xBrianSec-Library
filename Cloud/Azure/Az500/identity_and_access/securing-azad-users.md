
# Securing Az AD Users – Authentication, Authorization and Identity Federation

> **Original text preserved**, then augmented with theory, commands, and Q&A (✅ answers).

---

## Original Notes (Preserved Verbatim)

Authentication, authorization and identity federation

	• Federation
		○ Example
			§ User wants to sign in to app, the apps don’t do the auth, they are configured to trust the idp. There is a metadata xml file that has the idps public key. 

Managing az ad identity protection

	• Blade: Security > Identity protection

	• Open new windows > az id > licenses > manage your licenses > products > service plan details >  az ad p2 
	• (enterprise mobility + security trial)


	• Ms does not tell us how they rate "user risk level" high, med, low
	• User Risk Policy
			§ We can choose 
				® What users
				® Sign-n risk
				® Controls
					◊ Access- block or allow
	• Sign-in policy
				□ We can choose 
					® What users
					® Sign-n risk
					® Controls
						◊ Access- block or allow
	• MFA
				□ We change
					® Assignments to users
					® Control-require azad mfa registration

	• Reports
		○ Risky users
			§ Risk state, level
		○ Risky workload ids
			§ Servprincs, app id, risk state
		○ Risky sign ins
			§ Date, user, ip, location, risk state
		○ Risk detections
			§ Detection time, user, ip, location, detection type, risk state, risk level


Enabling Passwordless Authentication

	• Use doesn’t have to register first,
		○ Authenticator will ask the user to regisiter when asked for the number
		○ Add work or account, scan qr code. If not setup you can enable phone sign-in
	• The first setup
		○ IN AZ AD Tenant > auth methods, MA settings, enable and target=enable > auth mode= passwordless > save


Implementing Password protection

	• Use if auth includes user pws
	• In az ad tenant
		○ Can reset up pw
		Ø Auth methods
			§ Phone
			§ Revoke mfa sessions
		○ Security > auth methods  > pw protection
			§ Lockout threshhold default is 10x
			§ Lockout duration is 60 seconds
			§ Enforce custom list
				□ Ban list
			§ Enable Password protection for DCs
			§ Mode
				□ Enforced
				□ Change to audit?


Enabling Az ad sso

	• Çan use with ad on prem
	• Azure ad gallery is a catalog of thousands of apps to deploy and configure sso and automated user provisioning. 
		○ You can leverage prebuilt templates to connect users to their apps
	• Can add an on-prem app, using a pw sso, with application proxy
	• Can create sso for some apps features
	• Can be custom
	• Not all apps use the same procedure for setup
	• As user can visit assigned apps portal
		○ Myapplications.microsoft.com
	• Check app sso config
		○ Az ad > Apps > all apps > choose app > manage|sso on left >  
			§ Some apps require attributes (user details )and claims (are what attr the app is wanting)
			§ SAML works usually allowsfor it
			§ Can download certs to use with app, shows that az ad the idp is trusted
			§ Make sure to test


Exploring the Microsoft Entra admin center

	• Az ad
		○ Id governance
			§ Entitlement management
				□ External user lifecycle
					® Used for external partners, contractors
				□ External ids
				□ Identity providers

	• Protect and secure
		○ Conditional access
		○ Idp
		○ Auth methods
		○ Password reset



Enabling Self service password reset  (sspr)
	• Az ad > security auth methods > policies > 
		○ In mfa settings
			§ Under user/groups auth mode =
				□ Passwordless
				□ Push
				□ Any
			§ Email otp
				□ Configure 
					® Allow external users to use otp
		○ Az ad > user > pw reset
			§ Default = none
			§ Admins are always enabled for sspr, and are required to use 2 auth methods to reset


Which configuration options are available when using the Microsoft Entra Admin Center?

			Groups
			Identity Governance
			Resource groups
			Management groups

Which are common SSO standards?
			SAML
			OSI
			OpenID
			XML

Which benefit is realized by configuring user SSPR?

		Reduces Azure AD costs
		Dynamic group membership
		Less burden on the help desk.
		Hardened user sign-ins



Which item is related to configuring Password Protection?
		MFA
		Lockout threshold
		Administrative Unit
		Passwordless login

You need to ensure assistant cloud technicians have access to view storage accounts for a specific resource group only. Which type of access control should you configure?

		Azure Policy
		Azure Management Group
		RBAC
		ABAC

> 
Users complain that after Passwordless Login has been configured, they are still prompted to enter their password when signing in using the Azure AD account. What is the problem?

		Users should click “Use an app instead”
		Users do not have MFA enabled for their accounts
		Users have not configured alternate notification methods
		Users have not been added to an Administrative Unit

---

## Augmented Theory
- **Identity Protection (P2)** evaluates risk (e.g., leaked creds, unfamiliar sign-in, impossible travel). Policies can **block** or require **password reset/MFA**.
- **Passwordless** requires Authenticator registration; number matching is anti-phish. FIDO2 keys are another option.
- **Password Protection**: global/custom banned password lists + smart lockout; can extend to on-prem DCs via agent.
- **SSO**: Prefer SAML or OpenID Connect. Claims mapping varies per app; test with the app’s SSO blade.
- **SSPR**: Admins always enabled; users need two registered methods.

## Q&A (✅ Correct Answers)
- **Entra Admin Center options available?** → Groups ✅, Identity Governance ✅  
- **Common SSO standards?** → SAML ✅, OpenID ✅  
- **SSPR benefit?** → Less burden on the help desk ✅  
- **Password Protection related item?** → Lockout threshold ✅  
- **Restrict storage view in RG only?** → RBAC ✅  
- **Passwordless still asks for password. Why?** → Users should click “Use an app instead” ✅  
