

the linkage of Group Policy Objects (GPOs) to Active Directory containers such as sites, domains, or organizational units. The GPLink attribute on these containers holds the information about which GPOs are linked to them, and in what order they should be applied.
GpLinks can be enforced or not, and OUs can block inheritance or not.



GPLink Enforcement


If a GpLink is enforced, the associated GPO will apply to the linked OU and all child objects, regardless of whether any OU in that tree blocks inheritance.

If a GpLink is not enforced, the associated GPO will apply to the linked OU and all child objects, unless any OU within that tree blocks inheritance.




Find GpLink of "Domain Controllers" OU

To find the GpLink status of the "Domain Controllers" OU, you can use the following PowerShell command:

The gpLink value will either be ;1 if it's enforced or ;0 if it's not enforced.

```
Get-DomainOU -Identity "Domain Controllers" | Select-Object ne, gpLink | Format-List

```

