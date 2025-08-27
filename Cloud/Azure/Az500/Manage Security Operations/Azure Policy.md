# Managing Az Policies

## What Is Azure Policy?
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

## Using Azure Policy to Audit Compliance

Purpose of Azure Policy Assignments
    • Enforce rules across management groups, subscriptions, or resource groups
    • Examples:
        ○ Ensure TDE is enabled for SQL
        ○ Enforce allowed regions for resource deployment
        ○ Check if disaster recovery is configured for VMs

Starting in the Portal
    1. In Azure portal, search “Policy”
    2. Opens Azure Policy blade with:
        ○ Overview
        ○ Assignments
        ○ Definitions
        ○ Compliance

Definitions Tab
    • View policy definitions and initiative definitions
    • Filter by:
        ○ Definition Type: Policy or Initiative
        ○ Initiatives are groups of related policies whether its built in or custom created
        ○  Policy are individual
        ○ Search (e.g., "encrypt", "location")

Example: Allowed Locations Policy
    1. Filter or search for "allowed locations"
    2. View the JSON policy definition
        ○ parameters: listOfAllowedLocations (string array)
        ○ effect: deny
        ○ Condition: If resource location is not in allowed list, deny deployment

Assign the Policy
Click Assign → Steps:
1. Basics (Scope and Exclusions)
    • Choose Scope:
        ○ Management Group
        ○ Subscription
        ○ Resource Group (e.g., App1)
    • Optional: Add Exclusions (e.g., exclude a project or resource)
2. Assignment Name
    • Example: Allowed locations for App1 resource group
3. Advanced (Optional)
    • Use Add Resource Selector to limit policy to specific resource types or locations
    • Skipped in this case (applies to everything in App1)
4. Parameters
    • Set the allowed region (e.g., East US)
    • Can select multiple regions if needed
5. Remediation (Optional)
    • Policy applies only to new resources
    • Existing resources require a remediation task
    • May need a managed identity for automatic remediation
6. Review + Create
    • Validate settings and click Create

Confirm Policy Assignment
    • Go to Assignments tab
    • Set Scope filter to App1 resource group
    • See assignment listed with name and compliance state

View Compliance State
    • Go to Compliance tab
    • Find policy assignment (e.g., Allowed Locations)
    • State will show as Compliant

Test Denial Enforcement
    1. Try to create a resource (e.g., Storage Account)
    2. Set:
        ○ Resource Group: App1
        ○ Region: Central US (not allowed)
    3. Azure blocks creation:
        ○ Error: “Policy validation failed”
        ○ Message: Region is not in allowedLocations

Summary
    • Azure Policy lets you enforce, audit, or auto-remediate compliance
    • Supports built-in or custom JSON policies
    • Assign to any scope (MG, sub, RG)
    • Monitor enforcement under Assignments and Compliance

## Creating and Assigning a Custom Policy

Why Use a Custom Policy?
    • Built-in policies may not cover highly specific business or technical requirements.
    • Example: Only allow Ubuntu 20.04 VMs in a specific resource group.

Steps to Create a Custom Policy (Portal)
1. Open Azure Policy
    • Search for “Policy” in the Azure Portal
    • Go to Definitions tab
2. Create New Policy Definition
    • Click Add policy definition
    • Choose Definition location: e.g., Azure subscription 1
    • Name: Ubuntu Forever
    • Category: Create new → Virtual Machines
3. Paste JSON Policy Definition
    • JSON includes:
        ○ "if": Checks if resource is VM, disk, or scale set
            § Matches:
                □ "publisher": "Canonical"
                □ "offer": "UbuntuServer"
                □ "sku": "20.04-LTS"
        ○ "then": effect = deny if condition is not met
    • Save policy

Assign the Custom Policy
1. Click Assign from the policy definition screen
    • Scope: Choose App1 resource group
    • No exclusions
    • Assignment Name: Ubuntu Forever
    • Status: Enabled
2. Click through:
    • No Advanced filters
    • No Parameters (this policy has none)
    • No Remediation tasks
    • Click Create

Test the Assignment
✅ Allowed:
    • Deploy Ubuntu 20.04 VM in App1 RG → Passes policy check
❌ Denied:
    • Deploy Windows Server or Ubuntu 18.04 in App1 RG → Fails with policy violation
    • Policy error message includes name: Ubuntu Forever
    • Clicking Policy Details shows JSON and assignment info
✅ Not Affected:
    • Create any VM in App2 RG → Passes (policy not assigned to App2)

Policy Lifecycle Notes
    • Custom policies show Type = Custom under Definitions
    • Can filter definitions by:
        ○ Search term: e.g., Ubuntu
        ○ Category: e.g., Virtual Machines

Deleting a Custom Policy
    • Must first remove all assignments
    • Otherwise deletion will fail

Summary
    • Custom policies let you define fine-grained, resource-specific controls
    • Assignment scoping ensures policy only applies where needed
    • Built-in and GitHub examples can help with writing custom policy JSON
    
     
## Assigning Az policy using cli



Overview
Azure Policy assignments can be created via:
    • PowerShell
    • Azure CLI
Useful for automation, scripting, and environments without GUI access.

PowerShell: Assigning a Policy
1. Set the Resource Group Variable
$rg = Get-AzResourceGroup -Name "App1"
2. Retrieve the Policy Definition
$definition = Get-AzPolicyDefinition | Where-Object {
  $_.Properties.DisplayName -eq "Audit virtual machines without disaster recovery configured"
}
3. Create the Policy Assignment
New-AzPolicyAssignment `
  -Name "VMs-DR Enabled" `
  -DisplayName "Check for VM Disaster Recovery" `
  -Scope $rg.ResourceId `
  -PolicyDefinition $definition
    • -Scope: Must be the resource ID (not just the name)
    • -PolicyDefinition: Uses the full object retrieved earlier

Confirm in Portal
    • Go to Azure Policy → Assignments
    • Set Scope to the resource group (App1)
    • Confirm policy appears (e.g., Check for VM Disaster Recovery)

Azure CLI: Assigning a Policy
1. List All Policy Definitions by Display Name
az policy definition list --query [].displayName
2. Gather Required IDs
    • Go to the portal → Find the Policy Definition ID
    • Go to the Resource Group → Copy its Resource ID
3. Create the Assignment via CLI
az policy assignment create \
  --name "UbuntuAssignment1" \
  --policy "/subscriptions/<sub-id>/providers/Microsoft.Authorization/policyDefinitions/<policy-id>" \
  --scope "/subscriptions/<sub-id>/resourceGroups/App1"
Parameters:
    • --name: Unique name for the assignment
    • --policy: Full resource path to the policy definition
    • --scope: Full resource path to the assignment scope (e.g., RG)

Confirm CLI Assignment in Portal
    • Azure Policy → Assignments
    • Set Scope to App1
    • Look for UbuntuAssignment1 listed

Notes
    • Both PowerShell and CLI require:
        ○ Policy Definition ID
        ○ Scope Resource ID
    • Portal is helpful for copying those values directly
    • Assignments created this way are active immediately

## Managing policy initiatives

What Is a Policy Initiative?
    • A grouping of related policy definitions
    • Assigned as a single unit for streamlined governance
    • Useful for applying multiple policies at once for:
        ○ Regulatory compliance (e.g., PCI-DSS, NIST SP 800-171)
        ○ Organizational standards (e.g., web app security settings)

Viewing Built-in Initiatives
    1. Go to Azure Policy
    2. Navigate to Definitions
    3. In Definition type dropdown → Select Initiative
    4. Examples:
        ○ PCI v3.2.1:2018
        ○ NIST SP 800-171 Rev.2

Assigning a Built-in Policy Initiative (e.g., PCI DSS)
1. Select Initiative
    • Click on PCI v3.2.1:2018
    • Click Assign
2. Define Scope
    • Choose:
        ○ Subscription
        ○ Resource Group (e.g., App1)
    • Optional: Add Exclusions
3. Advanced Options (optional)
    • Narrow assignment to:
        ○ Specific resource types
        ○ Specific locations
4. Parameters
    • Provide required values for any parameters
    • Some built-in initiatives prompt for multiple inputs
5. Remediation (optional)
    • Enable remediation tasks to fix existing non-compliant resources
    • May require managed identity
6. Non-Compliance Messages (optional)
    • Add guidance to help admins fix non-compliant resources
7. Review and Create
    • Click Create
    • Confirm success in Assignments view (scope = App1)

Creating a Custom Initiative
1. Go to Definitions → Click Add Initiative Definition
    • Scope: Choose Subscription or Management Group
    • Name: e.g., Web App Security
    • Category: Choose existing (e.g., Security Center) or create new
2. Add Policy Definitions
    • Click Add policy definitions
    • Filter (e.g., App Service)
    • Select relevant policies, such as:
        ○ Require HTTPS for App Services
        ○ Disable public access to App Services
        ○ Enforce TLS 1.2
        ○ Enable Defender for App Services
3. (Optional) Organize Policy Groups
    • Group related policies for easier visibility
4. Skip Parameters (if none needed)
    • Or define default values for parameterized policies
5. Create the Initiative

Assigning a Custom Initiative
    • Either click Assign from the success page
    • Or go to Assignments tab → Click Assign
    • Scope: e.g., Subscription
    • Review and Create

Viewing and Validating Assignment
    • Go to Assignments
    • Scope: Filter to Subscription or RG (e.g., App1)
    • See initiative listed (e.g., Web App Security)
    • Use Compliance tab to check evaluation status (may take time)

Notes
    • Initiatives reduce management overhead
    • Required for implementing regulatory frameworks
    • Useful for applying organization-specific bundles of policies

