### GitHub Token Management and Usage

#### Recognize GitHub Token
- GitHub tokens start with the prefix `ghp_` followed by 35 characters that can include both uppercase and lowercase letters, and numbers.
  Example: `ghp_0OKFEaAOKFwbH`

#### Login Using GitHub Token
```bash
gh auth login
```
1. Run the `gh auth login` command.
2. Follow the prompts:
    - Choose GitHub.com
    - Select HTTPS for Git operations
    - Decline to authenticate Git with your GitHub credentials
    - Choose to authenticate GitHub CLI using an authentication token
3. Generate a Personal Access Token [here](https://github.com/settings/tokens). Minimum required scopes are `repo` and `read:org`.
4. Paste your authentication token when prompted.

Alternatively, use the command directly with a token:
```bash
gh auth login --with-token <token>
gh auth login -h github.test.com --with-token <token>

```

#### Clone Repositories Using GitHub CLI
- Clone all repositories from a specific organization:
  ```bash
  gh repo list test-zlop1-tfe-modules --visibility=private --limit 4000 | while read -r repo _; do
    gh repo clone "$repo" "$repo"
  done
  ```

#### List All Organizations a Token Has Access To
```bash
gh org list
```
- Example output:
  ```
  Showing 3 of 3 organizations
  test-zlop1-tfe-modules
  test-zlop1-tfe-modules-dev
  test-zlop1-dev-tfe-modules
  ```

#### List All Repositories in an Organization
```bash
gh repo list test-zlop1-tfe-modules
```
- Example output:
  ```
  Showing 30 of 547 repositories in test-zlop1-tfe-modules
  nE DESCRIPTION INFO UPDATED
  ABCD-zlop1-tfe-modules/terraform-azurerm-appgateway This repository was generated using the API script private about 7 minutes ago
  test-zlop1-tfe-modules/terraform-azurerm-mssql-managed-instance Manages a Microsoft SQL Azure Managed Instance. private about 52 minutes ago
  zlop1test-tfe-modules/terraform-aws-lambda-function Provides a Lambda Function resource private about 18 hours ago
  ```

#### Test All Tokens for Authentication (Requires GitHub CLI)
```powershell
Get-Content .\ghp_tokens.txt | %{$env:GH_TOKEN = $_; echo "Trying token: $env:GH_TOKEN"; gh org list}
```

#### List Git Repositories with a PAT and Clone
```bash
git clone https://<PAT>@dev.azure.com/yourOrgne/yourProjectne/_git/yourRepone
```

#### List Logs of a File
```bash
git log -p -- jfrog-token-check.yaml
```
