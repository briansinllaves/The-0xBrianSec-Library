# Managing Az Policies

## What Is Azure Policy?

* A governance tool to enforce rules and effects on Azure resources.
* Controls what can be deployed, how it’s configured, and where it can be deployed.

### Azure Policy vs RBAC

* **RBAC** → Controls *who* can perform *what* actions.
* **Azure Policy** → Controls *what* resources can be created/configured and *how*.
* Example:

  * RBAC: *Techs can deploy VMs*
  * Policy: *Only Linux VMs of size B2ms can be deployed in West US*

---

## Built-in and Custom Policies

* **Built-in policies**: Ready-to-use for common compliance needs.
* **Custom policies**: Created using JSON definitions.

### Policy Structure

* JSON-based
* Can use parameters (e.g., allowed locations, VM sizes)
* Example parameter:

  ```json
  "allowedLocations": ["westus", "eastus"]
  ```

### Scope of Assignment

* Management Group → affects all subscriptions beneath it
* Subscription
* Resource Group
* Specific resource groups/projects can be excluded

---

## Policy Effects

| Effect                | Description                                                               |
| --------------------- | ------------------------------------------------------------------------- |
| **Append**            | Adds settings during deployment (e.g., storage account rules)             |
| **Audit**             | Logs non-compliance in Activity Log                                       |
| **AuditIfNotExists**  | Logs if a related configuration is missing (e.g., encryption not enabled) |
| **DeployIfNotExists** | Checks and deploys config if not present                                  |
| **Deny**              | Blocks resource creation if it violates policy                            |

---

## Tag Governance Example

* Policy can add default tags if none are specified
* Ensures consistent tagging across resources

---

## Policy Initiatives

* Group of multiple policies assigned together
* Example:

  * Enforce allowed regions
  * Require VM disk encryption
  * Require endpoint protection
* Benefits: Simplifies management and compliance reporting

---

## Management Tools

* Azure Portal
* Azure CLI
* PowerShell

---

## Using Azure Policy to Audit Compliance

### Assignments

* Apply rules at Management Group, Subscription, or Resource Group
* Example policies:

  * Ensure TDE is enabled for SQL
  * Enforce allowed regions
  * Audit VM disaster recovery

### Portal Walkthrough

1. Open **Policy** in Azure portal
2. Navigate tabs: Overview, Assignments, Definitions, Compliance

### Example: Allowed Locations Policy

* Search **Allowed locations** in Definitions
* JSON definition includes:

  * Parameters: `listOfAllowedLocations`
  * Effect: deny
  * Condition: block resource creation if not in allowed list

---

## Assigning a Policy

1. Basics → Select scope (MG, Sub, RG)
2. Assignment Name → e.g., *Allowed locations for App1*
3. Advanced (optional) → Resource selectors
4. Parameters → Choose allowed regions
5. Remediation (optional) → Enable remediation tasks with managed identity
6. Review + Create

---

## Compliance State

* View in **Assignments** and **Compliance** tabs
* Attempt deployment outside allowed regions → denied with **Policy validation failed**

---

## Creating a Custom Policy

### Example: Only allow Ubuntu 20.04 in App1 RG

1. Create Policy Definition → Name: *Ubuntu Forever*

2. JSON checks resource properties:

   * `publisher`: Canonical
   * `offer`: UbuntuServer
   * `sku`: 20.04-LTS
   * Effect: deny

3. Assign to App1 RG

4. Test:

   * ✅ Ubuntu 20.04 allowed
   * ❌ Windows/Ubuntu 18.04 denied

---

## Deleting a Custom Policy

* Remove all assignments before deleting definition

---

## Assigning Policies via CLI/PowerShell

### PowerShell

```powershell
$rg = Get-AzResourceGroup -Name "App1"
$definition = Get-AzPolicyDefinition | Where-Object {
  $_.Properties.DisplayName -eq "Audit virtual machines without disaster recovery configured"
}
New-AzPolicyAssignment `
  -Name "VMs-DR Enabled" `
  -DisplayName "Check for VM Disaster Recovery" `
  -Scope $rg.ResourceId `
  -PolicyDefinition $definition
```

### CLI

```bash
az policy definition list --query [].displayName
az policy assignment create \
  --name "UbuntuAssignment1" \
  --policy "/subscriptions/<sub-id>/providers/Microsoft.Authorization/policyDefinitions/<policy-id>" \
  --scope "/subscriptions/<sub-id>/resourceGroups/App1"
```

---

## Policy Initiatives

* Group multiple policies for compliance frameworks (PCI, NIST, etc.)
* Built-in examples:

  * PCI DSS v3.2.1
  * NIST SP 800-171

### Assigning Initiatives

* Assign to Sub or RG
* Provide parameters as required
* Optionally enable remediation tasks

### Custom Initiatives

* Define under **Definitions > Add Initiative**
* Example: *Web App Security* → Require HTTPS, enforce TLS 1.2, disable public access

---

## Summary

* **Azure Policy** enforces configuration standards.
* **RBAC vs Policy** → Who can do vs What can be done.
* Supports **built-in** and **custom JSON policies**.
* Assign at **MG, Sub, RG** scope.
* Monitor via **Assignments** and **Compliance**.
* Use **Initiatives** to bundle policies for frameworks or internal standards.
