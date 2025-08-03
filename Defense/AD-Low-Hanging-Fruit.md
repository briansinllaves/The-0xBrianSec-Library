# LDAP and AD Security Hardening

## LDAP Security Enhancements

**Overview:** LDAP channel binding and signing help prevent man-in-the-middle (MitM) attacks during directory authentication. Without them, attackers can intercept or alter traffic using tools like `ntlmrelayx`.

**Hardening:**
**Enable LDAP signing and channel binding** to secure directory authentication.
**Remediation:** Set `Domain controller: LDAP server signing requirements` to **Require signature** at:
`Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options`

## Windows Firewall and Network Protection

**Overview:** DHCPv6 and WPAD can be abused to force victims into malicious proxy configurations or inject rogue network settings. These attacks can lead to credential capture or traffic redirection.

**Hardening:**
**Block DHCPv6 traffic** and **disable WPAD** if unused.
**Remediation (DHCPv6):** Add inbound rules to block UDP port 546:
`Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security`
**Remediation (WPAD):** Set **Turn off WPAD** at:
`Computer Configuration -> Policies -> Administrative Templates -> Network -> Network Isolation`

## Name Resolution and Password Policies

**Overview:** LLMNR and NBT-NS are common lateral movement vectors. Attackers use Responder or Inveigh to poison name requests and capture NTLM hashes.

**Hardening:**
**Disable LLMNR and NBT-NS**, and enforce **strong password policies**.
**Remediation (LLMNR):** Set **Turn off Multicast Name Resolution** to Enabled at:
`Computer Configuration -> Policies -> Administrative Templates -> Network -> DNS Client`
**Remediation (Password):** Set **Minimum password length** to 14 characters at:
`Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Password Policy`

## Credential Protection

**Overview:** SMBv1, NTLM, and unprotected credentials allow relaying and credential theft. Tools like Mimikatz, PetitPotam, and SMBRelay exploit these gaps.

**Hardening:**
**Enable Defender Credential Guard**, **disable SMBv1**, and enforce **SMB signing and NTLMv2-only policies**.
**Remediation:**

* Enable Credential Guard using Device Guard readiness tool.
* Disable SMB1 in Windows Features.
* Set `Microsoft network server: Digitally sign communications (always)` to Enabled at:
  `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options`
* Set `LAN Manager authentication level` to **Send NTLMv2 response only** at the same location.

## Managed Service Accounts and Local Admins

**Overview:** Shared local admin credentials and unmanaged service accounts enable lateral movement and persistence. Attackers target these accounts for repeated access.

**Hardening:**
**Use gMSAs** and **deploy LAPS** for local admin password rotation.
**Remediation:**

* Monitor with PowerShell: `Get-ADServiceAccount`
* Install and configure LAPS via:
  `Computer Configuration -> Policies -> Administrative Templates -> LAPS`

## Privileged Access Management & MFA

**Overview:** Admin privileges without separation increase risk of privilege escalation. Lack of MFA allows token/session theft. PAM limits this through role-based elevation and isolation.

**Hardening:**
**Deploy PAM** and **enforce MFA** for privileged accounts.
**Remediation:**

* Configure PAM forest and trust settings using Server Manager.
* Use Azure AD or on-prem MFA and enforce sign-in policies.

## Security Policies and Auditing

**Overview:** Lack of lockout policies and audit logging enables brute force and stealth persistence. Attackers exploit unlimited login attempts and weak event visibility.

**Hardening:**
**Enforce lockout thresholds** and **enable auditing for key events**.
**Remediation:**

* Set account lockout threshold in:
  `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy`
* Configure audit logging at:
  `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration`

## SIDHistory and Credential Handling

**Overview:** Attackers abuse SIDHistory to maintain access across trusts or elevate privileges. They can inject SIDHistory entries to impersonate privileged users.

**Hardening:**
**Restrict SIDHistory changes** and use **GPO filtering** to prevent propagation.
**Remediation:**

* Adjust ACLs on `AdminSDHolder`
* Use Security Filtering in Group Policy for affected GPOs

## Service Accounts and Credential Storage

**Overview:** Shared service accounts simplify attacker movement. Separate accounts reduce blast radius if compromised.

**Hardening:**
**Use unique service accounts per domain service**.
**Remediation:**

* Create separate accounts using Active Directory Users and Computers

## AD Certificate Services & Trust Relationships

**Overview:** Weak trust settings and open forest trusts let attackers access external resources. ADCS misconfigs can enable domain persistence via golden certs.

**Hardening:**
**Apply Selective Authentication** and **harden certificate services**.
**Remediation:**

* Configure Selective Auth and ACLs in AD Domains and Trusts

## Kerberos and Authentication Policies

**Overview:** Kerberos tickets cached too long or poorly configured policies let attackers replay TGTs or maintain access post-password change.

**Hardening:**
**Force password changes**, **purge Kerberos cache**, and **tighten ticket policies**.
**Remediation:**

* Set `Prompt user to change password before expiration` at:
  `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options`
* Set `Maximum password age` and run `klist purge` after changes
* Configure Kerberos settings in:
  `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies`
* Flush tickets with PowerShell:
  `Invoke-Command -ScriptBlock {klist -li 0x3e7 purge} -ComputerName DCName`
* Restart Domain Controllers via Server Manager or:
  `Restart-Computer -Force`

## Local Security Authority (LSA) Protection

**Overview:** Attackers use Mimikatz and similar tools to extract credentials from LSASS memory. LSA protection prevents loading unsigned code into LSASS.

**Hardening:**
**Enable LSA protection** to block injection attacks.
**Remediation:**

* Set `RunAsPPL` registry key:
  `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` → `RunAsPPL` = `1`
* Or configure via Group Policy:
  `Computer Configuration -> Policies -> Administrative Templates -> System -> Local Security Authority`

## Remote Desktop Services (RDP) Security

**Overview:** Attackers brute-force RDP, exploit weak configurations, or harvest credentials via clipboard and drive redirection.

**Hardening:**
**Restrict RDP access** and **harden session settings**.
**Remediation:**

* Use Network Level Authentication (NLA)
* Disable clipboard, printer, and drive redirection in GPO
* Enforce strong password and lockout policies
* Monitor for excessive RDP login attempts in event logs

## Administrative Shares and Remote Access

**Overview:** Attackers leverage hidden shares like C\$, ADMIN\$ for lateral movement after credential theft.

**Hardening:**
**Restrict access to administrative shares** and **monitor remote access attempts**.
**Remediation:**

* Limit `Administrators` group membership
* Audit share usage
* Disable unused shares via registry or GPO if not needed
