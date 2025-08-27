# What Is Azure Policy?
    • A governance tool to enforce rules and effects on Azure resources.
    • Controls what can be deployed, how it's configured, and where it can be deployed.

Azure Policy vs RBAC
    • RBAC = Controls who can perform what actions.
    • Azure Policy = Controls what resources can be created/configured and how.
Example:
    • RBAC: "Techs can deploy VMs."
    • Policy: "Only Linux VMs of size B2ms can be deployed in West US."

Built-in and Custom Policies
    • Built-in policies: Ready-to-use for common compliance needs.
    • Custom policies: Created using a JSON definition file.

Policy Structure
    • JSON-based
    • Can use parameters (e.g., allowed locations, VM sizes)
    • Example parameter: "allowedLocations": ["westus", "eastus"]

Scope of Assignment
    • Assign policies to levels of Azure hierarchy:
        ○ Management Group → affects all subscriptions beneath it
        ○ Subscription
        ○ Resource Group
    • You can exclude specific resource groups/projects even if they're under a broader scope

Policy Effects
Effect	Description
Append	Adds settings to a resource during deployment (e.g., storage account rules)
Audit	Logs non-compliance in Activity Log
AuditIfNotExists	Logs if a related configuration is missing (e.g., encryption not enabled)
DeployIfNotExists	Checks and deploys a resource/config if not already present
Deny	Blocks resource creation if it violates policy (e.g., wrong region)


Tag Governance Example
    • Policy can add default tags if none are specified
    • Ensures consistent tagging across environment

Policy Initiatives
    • A group of policies assigned together
    • Assigned like a single policy, but includes many under the hood
    • Example initiative:
        ○ Policy 1: Enforce allowed regions
        ○ Policy 2: Require VM disk encryption
        ○ Policy 3: Require endpoint protection
    • Benefit: Simplifies management and reporting

Management Tools
    • Azure Policy can be managed through:
        ○ Azure Portal
        ○ Azure CLI
        ○ PowerShell
