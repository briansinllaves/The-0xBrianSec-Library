"User": "Snapshotter" was assigned both full administrative privileges and EC2 management permissions.

Sensitive AWS keys for the Snapshotter profile were exposed in plain text within a build configuration file (BuildPipe.yaml).

Using these credentials, the team accessed multiple EC2 servers and S3 containers linked to the PROJECT-X environment. Inside one S3 container, they located an additional Artifactory access token for member002.

Azure blob storage account qstorq002 holds several containers with image deployment scripts and binaries, which include embedded SAS keys and Azure DevOps personal access tokens.

cloud-pulumi-demo\resources\prod.us-west-2.pulumi-777.eks-assets\.pulumi\archives\prod.us-west-2.pulumi-777.eks-assets\prod.us-west-2.pulumi-777.eks-assets.1.json

In the cloned repository XYZ-lightbulbcloud\legacy-keys\azure-ad\, the script Fetch-AzureADXYZGroups.ps1 contained hardcoded credentials for Azure service principal "98765432".

This enabled access to the Azure service principal and enumeration of linked assets.

Within another pipeline configuration (deploy.yaml), credentials for AWS storage account BKY4 were discovered, granting access to S3 containers. Artifactory credentials were also found in a backup JSON file at

cloud-pulumi-demo\resources\prod.us-west-2.pulumi-777.eks-assets\.pulumi\archives\prod.us-west-2.pulumi-777.eks-assets\prod.us-west-2.pulumi-777.eks-assets.16.json. These Artifactory credentials were confirmed by listing available repositories.

D:\Users\jdoe\Documents\s3backup\cloud-pulumi-demo
\resources\prod.us-west-2.pulumi-777.eks-assets\.pulumi\stacks

prod.us-west-2.pulumi-777.eks-assets.json.bak

The security assessment team leveraged discovered credentials for AWS storage account QdS, which provided access to the S3 container "cloud-pulumi-demo" containing JSON backup files. This led to the identification of plaintext Artifactory credentials for user "x" with access to [https://artifacts-central.XYZ.com:443/artifactory/z](https://artifacts-central.XYZ.com:443/artifactory/z0).

In the cloned repository, the script Fetch-AzureADXYZGroups.ps1 was again found with hardcoded credentials for Azure service principal "11a3-cc-d09". This permitted access to the Azure service principal and enumeration of associated resources.