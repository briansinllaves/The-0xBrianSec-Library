### Azure DevOps Commands

#### Get Connection Details
```shell
GET ConnectionDetails as another.user@ABCD.com
```

#### Get All Pipelines
```shell
Get-Pipelines as another.user@ABCD.com
```

#### Get Details of a Specific Pipeline
```shell
Get-Pipeline -PipelineId 652 as another.user@ABCD.com
```

#### Get Runs of a Specific Pipeline
```shell
Get-PipelineRuns -PipelineId 652 -OutObject -NoOutput as another.user@ABCD.com
```

#### Get Artifacts of a Specific Pipeline
```shell
Get-PipelineArtifacts -PipelineId 652 as another.user@ABCD.com
```

#### Download Artifacts of a Specific Pipeline
```shell
Download-PipelineArtifacts -PipelineId 652 -OutputDirectory .\ as another.user@ABCD.com
```

#### List Build Definitions in a Project
```shell
az pipelines build definition list -p "dad-cloud" as another.user@ABCD.com
```

#### Show a Specific Build Definition
```shell
az pipelines build definition show --id 652 -p "dad-cloud" as another.user@ABCD.com
```

#### Fetch Repository Information from Artifactory
```shell
curl -u ci_us-ifs-NotNextGen-stg-helm:eyJ2O.... https://artifacts-west.ABCD.com/artifactory/api/repositories > repositories From "Publish Helm Chart to Artifactory" pipeline logs
```

#### Invoke Web Request to Get Build Information from Azure DevOps
```shell
Invoke-WebRequest -Uri "https://dev.azure.com/$script:DevopsOrganization/dad-cloud/_apis/build/builds" -Headers $headers as another.user@ABCD.com
```

### Accessing `/etc/kubernetes/azure.json` in AKS

#### List Nodes in the Cluster
```shell
kubectl get nodes
```

#### Open a Shell Session on a Node
```shell
kubectl debug node/<node-ne> --image=mcr.microsoft.com/dotnet/runtime-deps:6.0
```

#### Access the VMSS Instance
```shell
chroot /host
```

#### Retrieve and Display the `azure.json` File
```shell
cat /etc/kubernetes/azure.json
```

**Note**: Replace `<node-ne>` with the actual ne of the node you are targeting.

### Key Points

- **Security**: Ensure access to nodes is tightly controlled to prevent unauthorized access to sensitive credentials.
- **Best Practices**: Regularly rotate credentials and monitor logs for any suspicious activities.