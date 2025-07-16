"Userne": "ImageFactory-Dev", has a administratoraccess policy and amazonec2fullaccess attached.

AWS Credentials for the Image Builder-dev account were found in cleartext in a pipeline definition (CleanImages-Dev-TableQuery_855.yaml).

The team used the credentials to access various ec2 instances and s3 buckets related to DAD. Within the aws-pulumi-poc bucket, the team discovered another Artifactory token for user001.

Azure storage account puserp001 contains several storage blobs, that contain Image provisioning scripts and executables that have embedded SAS tokens and Azure Devops PATs.

aws-pulumi-poc\clusters\test.us-east-1.pulumi-666.eks-resources\.pulumi\backups\test.us-east-1.pulumi-666.eks-resources\test.us-east-1.pulumi-666.eks-resources.1651711884638273045.json

In the pulled repository ABCD-zlop1-lightbulbcloud\sinllaves-legacy\azure-ad\, the file Get-AzureADABCDGroups.ps1, was found to have hardcoded credentials for Azure service principal "05c17cff-3400-43a2-b84b-3566f07". 

This allowed access to the Azure service 
principal account and enumeration for connected resources.

In a pulled pipeline definition (CleanImages-Dev-TableQuery_855.yaml),  AWS storage account AKZ3 credentials were found and can access S3 storage buckets. Artifactory credentials were found in a backup json file at

aws-pulumi-poc\clusters\test.us-east-1.pulumi-666.eks-resources\.pulumi\backups\test.us-east-1.pulumi-666.eks-resources\test.us-east-1.pulumi-666.eks-resources.16.json. The Artifactory credentials were validated by listing repositories.

C:\Users\bhous\Downloads\s3part3\aws-pulumi-poc\clusters\test.us-east-1.pulumi-666.eks-resources\.pulumi\stacks

test.us-east-1.pulumi-666.eks-resources.json.saved

The Pentest team used found credentials for AWS storage account AdS with access to S3 storage bucket "aws-pulumi-poc" that stores .json backup files. This lead to the finding of plaintext Artifactory credentials for user "ik01"  with access to [https://artifacts-west.ABCD.com:443/artifactory/w0-us-DLd-caam](https://artifacts-west.ABCD.com:43/artifactory/w0.

In the pulled repository, the file Get-AzureADABCDGroups.ps1, was found to have hardcoded credentials for Azure service principal "05c2-bb-f07". This allowed access to the Azure service principal account and enumeration for connected resources.