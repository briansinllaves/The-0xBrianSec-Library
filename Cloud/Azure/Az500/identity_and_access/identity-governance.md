# Identity and Access – Exercising Governance Principles

Mycompany.omnimicrosoft.com

Mycompany.widgets.com – attach the DNS suffix "widgets." This is what users/UPNs are attached to.

---

## Tenants and Subscriptions

* Tenants are like east-west, dev, test. You create users and groups—don’t need a sub.
* Subscriptions can be moved between tenants.
* Subscriptions are what give the power to create resources.

### Groups

* Groups can be static or dynamic.
* Dynamic is based off attribute.

### Admin Units

* Organize users and groups into an Admin Unit (AU) and delegate management of that AU to that admin.
* This means they can manage those users and groups in that AU.

### Tenant & Subscription Relationship

* If you have 2 tenants and 1 subscription, you can move the subscription to a different directory, but a subscription is tied to 1 tenant.

  * A tenant can have multiple subscriptions.
  * "Change directory" means "change tenant."

---

## Tenants

1. Tenants have their users, groups, apps.
2. Think of a tenant as an AD domain.

   * If you move a subscription from tenant to tenant, RBAC doesn’t follow the movement of a subscription from one Azure AD tenant to another.

```powershell
Connect-AzAccount -Tenant asff2342352we -UseDeviceAuthentication
```

---

## Management Groups

* Help with hierarchy setup and make it easier to point policies.

---

## Resource Groups

* Group resources, and can look at cost of all resources for an app.
* ??? What is a lock on a resource group??

---

## The Hierarchy

1. Management Group

   1. Tenant

      * Users/Groups
      * Subscriptions

        * Resources

          * Resource Groups
          * Creates resources

### Notes

* Management groups create a way to direct policy to each part of the tree.
* Management groups are not enabled by default.
* You can move subscriptions into different parts or heights of the hierarchy.
* Can add role assignment to a management group through group name and IAM.

  * This applies to all resources under the management group.
  * Role assignment member could be a group or user.
* You can give IAM in subscriptions or resource groups.

---

## Managing Resource Groups

* Through a resource group, you can move resources (like a VM) to another resource group, region, or subscription.

  * Can’t do that for many resources through their actual resource overview page—must go through resource management overview.
  * If you move a resource from one group to another, the IAM will be stripped away.
  * Any references targeting that resource ID will break with the new resource ID.

---

## Azure AD

* Azure AD Connect

  * Can sync on-prem AD domain.
  * Azure domain name needs to be the same as on-prem.

---
