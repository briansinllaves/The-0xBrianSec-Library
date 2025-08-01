
An OU, or Organizational Unit,  is used to organize and group objects like users, computers, and groups. Administrators can apply policies, permissions, and settings to a specific set of objects. 
Understanding the OU structure helps identify the organization's network layout (tiered assets), and potential security boundaries, technology and more. Additionally, OUs can be used to scope or set a boundary on administrative authority, so knowing which OUs have specific permissions can be important for privilege escalation and lateral movement. ADExplorer helps. 

Tactic: If an attacker compromised an account that had delegation authority and had the required Admin privileges, that could give a way privilege escalation and lateral movement across different OUs.
```
Get-domain ou
```
