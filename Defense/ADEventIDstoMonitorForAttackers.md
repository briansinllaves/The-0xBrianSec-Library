# Important AD Event IDs to Monitor for Hacker Activity

## Authentication and Logon Events

1. **Event ID 4768** – Kerberos Authentication Ticket (TGT) requested  
   Triggered when a user requests a Kerberos ticket, usually for initial logon.

2. **Event ID 4769** – Kerberos Service Ticket requested  
   Triggered when a service ticket is requested, indicating access to a specific service.

3. **Event ID 4624** – Successful Logon  
   Triggered when a user successfully logs on to the system. Pay attention to logons outside business hours or from unexpected locations.

4. **Event ID 4625** – Failed Logon  
   Triggered when a user logon attempt fails. Multiple failed attempts can indicate a brute-force attack.

5. **Event ID 4648** – Logon attempt with explicit credentials  
   Triggered when a logon is attempted with explicit credentials (e.g., via "Run as" or remote desktop).

6. **Event ID 4776** – The computer attempted to validate the credentials  
   Triggered when a machine tries to authenticate a user using NTLM (can indicate a potential pass-the-hash attack).

7. **Event ID 4672** – Special privileges assigned to new logon  
   Indicates when a logon occurs with high privileges, such as administrator or domain admin.

## Account Management

8. **Event ID 4720** – User account created  
   Triggered when a new user account is created, which could indicate account provisioning by an attacker.

9. **Event ID 4726** – User account deleted  
   Triggered when a user account is deleted. Unauthorized deletions can indicate malicious activity.

10. **Event ID 4740** – User account locked out  
    Triggered when a user account is locked due to too many failed login attempts, often part of a brute-force attack.

11. **Event ID 4732** – Member added to a security-enabled local group  
    Indicates changes to group memberships, which could indicate privilege escalation.

12. **Event ID 4756** – Member added to a security-enabled global group  
    Similar to Event ID 4732, but for global groups, often used for group-based privilege escalation.

13. **Event ID 4765** – SID history was added to an account  
    Indicates the addition of a SID (Security Identifier) history, often used in domain replication attacks.

## Privilege Escalation & Lateral Movement

14. **Event ID 4673** – A privileged service was called  
    Triggered when a service is called with high privileges, potentially indicating an attempt to escalate privileges.

15. **Event ID 4647** – User initiated logoff  
    Logs when a user logs off. This can be useful for detecting abnormal behavior, such as a quick logoff after suspicious activity.

## Group Policy and Domain Changes

16. **Event ID 5136** – A directory service object was modified  
    Triggered when an object in Active Directory is modified (e.g., user, group, or computer), useful for detecting unauthorized changes.

17. **Event ID 4728** – A member was added to a global security group  
    Indicates changes to group memberships, especially in privileged groups.

18. **Event ID 4735** – A group was changed  
    Indicates changes to a group, which could be an attempt to escalate privileges.

## Other Important Events

19. **Event ID 1102** – Audit log cleared  
    Triggered when an audit log is cleared, often by attackers trying to cover their tracks.

20. **Event ID 4771** – Kerberos pre-authentication failed  
    Failed Kerberos pre-authentication attempt, which could indicate an attempted Kerberos ticket attack or brute force.

21. **Event ID 539** – Account authentication request failed (for NTLM)  
    Failed NTLM authentication attempt. Multiple failures may indicate an attack using Pass-the-Hash or brute force.

## Admin and Sensitive Access

22. **Event ID 4670** – Permissions on an object were changed  
    Logs when permissions on an object (e.g., user or group) are changed, which could indicate privilege escalation.

23. **Event ID 5140** – Network share object accessed  
    Logs access to network shares. Unauthorized access attempts can indicate lateral movement.

24. **Event ID 4738** – User account changed  
    Indicates changes to user accounts (e.g., password change or group membership change).

---

## Key Things to Watch For

- Failed logons (**Event ID 4625**) from unexpected sources  
- Multiple failed Kerberos or NTLM requests (**Event ID 4769**, **Event ID 4771**)  
- Account lockouts (**Event ID 4740**), especially for privileged accounts  
- Creation or modification of sensitive accounts (e.g., admin or service accounts)  
- Unexpected group membership changes (**Event IDs 4732**, **4756**)  
- Audit log clearing (**Event ID 1102**)  
```
