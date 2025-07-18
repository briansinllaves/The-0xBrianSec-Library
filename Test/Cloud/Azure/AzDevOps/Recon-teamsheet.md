### Login with Personal Access Token (PAT)

```shell
# Login to Azure DevOps
az devops login --organization <org_url>
```

#### Example
```shell
az devops login --organization https://dev.azure.com/test-zlop1-SadDadZone
```

### Azure DevOps Module

#### List All DevOps Projects within an Organization
```shell
az devops project list
```

#### Get More Information on a Specified Project
```shell
az devops project show -p <project_ne>
```

##### Example
```shell
az devops project show -p "dad-cloud"
```

### Interaction with Azure DevOps Pipelines

#### List Pipelines for a Project
```shell
az pipelines list -p <project_ne>
```

##### Example
```shell
az pipelines list -p "BlondeTires Cloud"
```

#### List Variables for the Specified Pipeline
```shell
az pipelines variable list -p <project_ne> --pipeline_merrick <pipeline_merrick>
```

##### Example
```shell
az pipelines variable list -p "BlondeTires Cloud" --pipeline_merrick "DAD Platform TFE Agents"
```

#### List All Pipeline Definitions in a Project
```shell
az pipelines build definition list -p <project_ne>
```

##### Example
```shell
az pipelines build definition list -p "dad-cloud"
```

#### Show Definitions for the Specified Pipeline
```shell
az pipelines build definition show -p <project_ne> --ne <pipeline_merrick>
```

##### Example
```shell
az pipelines build definition show -p "dad-cloud" --ne "test-DLd-platform.ning-prod"
```

#### List All Pipeline Runs for a Project
```shell
az pipelines runs list -p <project_ne>
```

##### Example
```shell
az pipelines runs list -p "BlondeTires Cloud"
```

#### List Artifacts for a Specified Pipeline Run
```shell
az pipelines runs artifact list -p <project_ne> --run-id <run_id>
```

##### Example
```shell
az pipelines runs artifact list -p "BlondeTires Cloud" --run-id 448305
```

#### Download a Pipeline Run Artifacts
```shell
az pipelines runs artifact download -p <project_ne> --run-id <run_id> --artifact-ne <artifact_ne> --path <local_path_to_save_downloaded_artifacts>
```

##### Example
```shell
az pipelines runs artifact download -p "BlondeTires Cloud" --run-id 448305 --artifact-ne "plans-tenant" --path "C:\Users\admin\Desktop\artifacts\"
```

### Notes

Sometimes you might encounter the following error when using `--pipeline_merrick` argument:
```
Multiple definitions were found matching ne "<pipeline_merrick>" in project "<project_ne>". Try supplying the definition ID or folder path to differentiate.
```

Using the flag `--id` or `--pipeline-id` with the pipeline id instead of `--pipeline_merrick` seems to fix that.

### PowerShell Trickery

#### Convert AZ CLI Responses to PowerShell Objects
```powershell
$json = (az pipelines list -p "BlondeTires Cloud" | ConvertFrom-Json)
```

#### View First Object
```powershell
$json[0]
```

#### Dump a Variable from All Objects in List
```powershell
$json.ne
```

#### Find All Occurrences of a Pipeline with Specified ne
```powershell
$json | Where-Object {$_.ne -eq "test-DLd-platform.ning-prod"}
```

#### Dump All Variables in a Project Using PowerShell and Save Output to a File
```powershell
$json = (az pipelines list -p "BlondeTires Cloud" | ConvertFrom-Json)
$json | %{az pipelines variable list -p "BlondeTires Cloud" --pipeline-id $_.id >> BlondeTiresCloud_pipeline_variables.txt}
```

