### Terraform Enterprise (TFE) Pentester Cheat Sheet

#### Initial Setup:

1. **Install Terraform**:
   ```bash
   # Download and install Terraform from https://www.terraform.io/downloads.html
   ```

2. **Configure Terraform Enterprise (TFE) API Token**:
   ```bash
   export TFE_TOKEN="your_tfe_token"
   ```

3. **Set TFE Hostne**:
   ```bash
   export TFE_HOSTnE="your_tfe_hostne"
   ```

#### Enumeration and Reconnaissance:

1. **List All Workspaces**:
   ```bash
   curl \
     --header "Authorization: Bearer $TFE_TOKEN" \
     --header "Content-Type: application/vnd.api+json" \
     https://$TFE_HOSTnE/api/v2/organizations/your_organization/workspaces
   ```

2. **Get Workspace Details**:
   ```bash
   WORKSPACE_ID="your_workspace_id"
   curl \
     --header "Authorization: Bearer $TFE_TOKEN" \
     --header "Content-Type: application/vnd.api+json" \
     https://$TFE_HOSTnE/api/v2/workspaces/$WORKSPACE_ID
   ```

3. **List Runs in a Workspace**:
   ```bash
   curl \
     --header "Authorization: Bearer $TFE_TOKEN" \
     --header "Content-Type: application/vnd.api+json" \
     https://$TFE_HOSTnE/api/v2/workspaces/$WORKSPACE_ID/runs
   ```

4. **Get Run Details**:
   ```bash
   RUN_ID="your_run_id"
   curl \
     --header "Authorization: Bearer $TFE_TOKEN" \
     --header "Content-Type: application/vnd.api+json" \
     https://$TFE_HOSTnE/api/v2/runs/$RUN_ID
   ```

#### AWS Specific Recon:

1. **List AWS Resources**:
   ```bash
   terraform state list
   ```

2. **Show Detailed Information of a Resource**:
   ```bash
   terraform state show aws_instance.example
   ```

3. **Enumerate AWS IAM Users**:
   ```hcl
   data "aws_iam_account_alias" "current" {}

   data "aws_iam_user" "example" {
     user_ne = "example"
   }

   output "user_arn" {
     value = data.aws_iam_user.example.arn
   }
   ```

#### Azure Specific Recon:

1. **List Azure Resources**:
   ```bash
   terraform state list
   ```

2. **Show Detailed Information of a Resource**:
   ```bash
   terraform state show azurerm_virtual_network.example
   ```

3. **Enumerate Azure AD Users**:
   ```hcl
   data "azurerm_client_config" "example" {}

   data "azurerm_ad_user" "example" {
     user_principal_ne = "example@azuread.onmicrosoft.com"
   }

   output "user_id" {
     value = data.azurerm_ad_user.example.object_id
   }
   ```

#### Finding Authentication Credentials:

1. **Terraform Configuration Files**:
   - Check `.tf` files for hardcoded credentials. Look for `provider` blocks that may contain sensitive information.

2. **Terraform State Files**:
   - Review the `terraform.tfstate` file for stored credentials. This file contains detailed resource information and might have credentials in plain text.

3. **Environment Variables**:
   - Terraform often uses environment variables to store sensitive information. Check for variables such as `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `ARM_CLIENT_ID`, `ARM_CLIENT_SECRET`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, etc.

4. **TFE Environment Variables**:
   - In TFE, navigate to the workspace settings and check the "Variables" section. Look for sensitive information in environment variables defined for the workspace.

5. **Provider Configuration**:
   - Examine provider configuration blocks in Terraform files. Sensitive information might be embedded in these configurations.

   ```hcl
   provider "aws" {
     access_key = "your_access_key"
     secret_key = "your_secret_key"
     region     = "us-west-2"
   }

   provider "azurerm" {
     features {}
     client_id       = "your_client_id"
     client_secret   = "your_client_secret"
     subscription_id = "your_subscription_id"
     tenant_id       = "your_tenant_id"
   }
   ```

6. **Credentials Files**:
   - Check the default credentials files used by providers. For AWS, this is typically located at `~/.aws/credentials`. For Azure, it can be found at `~/.azure/credentials`.

7. **TFE Variables**:
   - TFE allows setting variables through the web UI. Check the workspace's "Variables" section for sensitive information.

