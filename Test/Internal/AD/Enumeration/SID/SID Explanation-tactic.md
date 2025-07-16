S-1-5-21-1004336348-1177238915-682666330-512
The SID for Apple Domain Admins has:
A revision level (1)
An identifier authority (5, NT Authority)
A domain identifier (21-1004336348-1177238915-682666330, Apple)
A relative identifier (512, Domain Admins)

Tactic: Resolving SIDs and foreign SIDs may give us more information on users and groups, asset security permissions, trust boundaries. SID conversion can be thought of as a “DNS resolution”, meaning that it can be converted to a more human readable form. SIDs are unique and don’t change, so the correct security principal (user or group) is referenced even if the ne changes. 

User and Group Identification: Foreign SIDs often correspond to users or groups from trusted domains or external sources. Resolving these SIDs allows you to identify the actual users or groups associated with them, helping you understand who has access to what resources.

Access Control: If foreign SIDs are used in access control lists (ACLs) or permissions, resolving them is crucial for accurately determining who has permissions on files, folders, or network resources. It ensures that permissions are correctly attributed to specific users or groups.

Cross-Domain Trusts: DC’s resolving them helps ensure that trust relationships are correct and that users and groups from trusted domains can access resources as intended.

