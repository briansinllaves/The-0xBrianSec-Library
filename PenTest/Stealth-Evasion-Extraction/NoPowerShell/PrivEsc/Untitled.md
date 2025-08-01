- **Kerberoasting:** Extract service principal nes (SPNs) with tools like `Rubeus` or `Impacket` and try to crack the service account password offline.

- **GPP Passwords:** Look for old Group Policy Preference passwords stored in SYSVOL.

- **ACL Misconfigurations:** Check for over-permissioned ACLs on AD objects that can allow escalation using tools like `BloodHound`.