IAM (Identity and Access Management):

Get information about the IAM user.
```
aws iam get-user
```

List the policies attached to a specific IAM user.
```
aws iam list-attached-user-policies --user-ne
```

List the MFA devices for a specific IAM user.
```
aws iam list-mfa-devices --user-ne <IAM_USER_nE>
```

List all IAM roles.
```
aws iam list-roles
```

List all IAM users.
```
aws iam list-users
```

EC2 (Elastic Compute Cloud):

List all EC2 instances.
```
aws ec2 describe-instances
```

List all EC2 regions.
```
aws ec2 describe-regions
```

List all EBS volumes.
```
aws ec2 describe-volumes
```

Connect to an EC2 instance via SSH.
```
Retrieve the EC2 instance's public IP address or public DNS ne

Pwsh

aws ec2 create-key-pair --key-ne MyKeyPair --query 'KeyMaterial' --output text | Out-File -FilePath .\MyKeyPair.pem 

File perm change

attrib +R .\MyKeyPair.pem 

ssh -i /path/to/key_pair.pem userne@instance_ip
```

Connect to an EC2 instance using AWS CLI.
```
Retrieve the EC2 instance's public IP address or public DNS ne
aws ec2 ssh --instance-id instance_ip
```

S3 (Simple Storage Service):

List all S3 buckets.
```
aws s3 ls
```

List objects within a specific S3 bucket.
```
aws s3 ls s3://your-bucket-ne/test/ --recursive
```

Download a file from an S3 bucket.
```
aws s3 cp s3://your-bucket-ne/path/in/bucket/filene.ext localfilepath
```

Download all contents of each S3 bucket.
```
unix
for bucket in $(aws s3 ls | awk '{print $3}'); do aws s3 sync s3://$bucket ./$bucket; done

pwsh
foreach ($bucket in $(aws s3 ls | ForEach-Object { $_.Split(' ')[-1] })) { aws s3 sync s3://$bucket .\$bucket }
```

Download all contents of  S3 buckets in a text file
```
$bucketList = Get-Content -Path "C:\path\to\bucket_list.txt" 

foreach ($bucket in $bucketList) { 

    aws s3 sync s3://$bucket .\$bucket 

}
```
Read the header or metadata of a file directly in the terminal.
```
aws s3api get-object --bucket aws-p --key "ABCDtest/FTP TESTING.txt" -
```

RDS (Relational Database Service):

List all RDS instances.
```
aws rds describe-db-instances
```

Lambda:

List all Lambda functions.
```
aws lambda list-functions
```

ECS (Elastic Container Service):

List all ECS clusters.
```
aws ecs list-clusters
```

Route 53 (DNS Service):

List all Route 53 hosted zones.
```
aws route53 list-hosted-zones
```

CloudFormation:

List all CloudFormation stacks.
```
aws cloudformation list-stacks
```

Secrets Manager:

List all Secrets Manager secrets.
```
aws secretsmanager list-secrets
```

SQS (Simple Queue Service):

List all SQS queues.
```
aws sqs list-queues
```

SNS (Simple Notification Service):

List all SNS topics.
```
aws sns list-topics
```

DynoDB:

List all DynoDB tables.
```
aws dynodb list-tables
```

CloudWatch:

Describe CloudWatch alarms.
```
aws cloudwatch describe-alarms
```

ECR (Elastic Container Registry):

Describe ECR repositories.
```
aws ecr describe-repositories
```

VPC (Virtual Private Cloud):

List all VPCs.
```
aws ec2 describe-vpcs
```

Elastic Load Balancing (ELB):

List all ELB load balancers.
```
aws elb describe-load-balancers
```

Auto Scaling:

Describe Auto Scaling groups.
```
aws autoscaling describe-auto-scaling-groups
```

Elastic Beanstalk:

List all Elastic Beanstalk applications.
```
aws elasticbeanstalk describe-applications
```

API Gateway:

Get information about all API Gateways.
```
aws apigateway get-rest-apis
```

Kinesis:

List all Kinesis data streams.
```
aws kinesis list-streams
```

CloudFront:

List all CloudFront distributions.
```
aws cloudfront list-distributions
```

AWS Glue:

List Glue databases.
```
aws glue get-databases
```

Amazon Redshift:

Describe Redshift clusters.
```
aws redshift describe-clusters
```

Amazon Athena:

List ned queries (saved queries).
```
aws athena list-ned-queries
```

Amazon EMR (Elastic MapReduce):

List all EMR clusters.
```
aws emr list-clusters --active
```

AWS Budgets:

List budgets.
```
aws budgets describe-budgets --account-id your-account-id
```

AWS Organizations:

List accounts within an organization.
```
aws organizations list-accounts
```

AWS WAF (Web Application Firewall):

List web ACLs.
```
aws waf list-web-acls
```

Amazon SageMaker:

List training jobs.
```
aws sagemaker list-training-jobs
```

Script to run all of them
```
# Require the user to configure AWS credentials before running this script
Write-Host "Make sure AWS CLI is configured with 'aws configure' before running this script."

# Function to execute AWS CLI command and process output
function Execute-AWSCommand {
    param (
        [string]$command,
        [string]$filene
    )
    try {
        # Run AWS CLI command
        $output = & cmd.exe /c $command
        if ($output.Length -gt 5) {
            $output | Out-File -FilePath "$filene.txt"
        } else {
            Write-Host "No output for $filene"
        }
    } catch {
        Write-Host "Error executing command: $command"
    }
}

# Define commands and their respective output file nes
$commands = @{
    "aws iam get-user" = "IAMUserInfo"
    "aws iam list-attached-user-policies --user-ne" = "IAMUserPolicies"
    "aws iam list-mfa-devices --user-ne" = "IAMUserMFA"
    "aws iam list-roles" = "IAMRoles"
    "aws iam list-users" = "IAMUsers"
    "aws ec2 describe-instances" = "EC2Instances"
    "aws ec2 describe-regions" = "EC2Regions"
    "aws ec2 describe-volumes" = "EBSVolumes"
    "aws s3 ls" = "S3Buckets"
    "aws rds describe-db-instances" = "RDSInstances"
    "aws lambda list-functions" = "LambdaFunctions"
    "aws ecs list-clusters" = "ECSClusters"
    "aws route53 list-hosted-zones" = "Route53Zones"
    "aws cloudformation list-stacks" = "CloudFormationStacks"
    "aws secretsmanager list-secrets" = "SecretsManagerSecrets"
    "aws sqs list-queues" = "SQSQueues"
    "aws sns list-topics" = "SNSTopics"
    "aws dynodb list-tables" = "DynoDBTables"
    "aws cloudwatch describe-alarms" = "CloudWatchAlarms"
    "aws ecr describe-repositories" = "ECRRepositories"
    "aws ec2 describe-vpcs" = "VPCs"
    "aws elb describe-load-balancers" = "ELBLoadBalancers"
    "aws elbv2 describe-load-balancers" = "ALBDetails"
    "aws autoscaling describe-auto-scaling-groups" = "AutoScalingGroups"
    "aws autoscaling describe-policies" = "AutoScalingPolicies"
    "aws elasticbeanstalk describe-applications" = "ElasticBeanstalkApplications"
    "aws elasticbeanstalk describe-environments" = "ElasticBeanstalkEnvironments"
    "aws apigateway get-rest-apis" = "APIGatewayDetails"
    "aws kinesis list-streams" = "KinesisDataStreams"
    "aws cloudfront list-distributions" = "CloudFrontDistributions"
    "aws glue get-databases" = "GlueDatabases"
    "aws glue get-jobs" = "GlueJobs"
    "aws redshift describe-clusters" = "RedshiftClusters"
    "aws athena list-ned-queries" = "AthenaSavedQueries"
    "aws athena list-work-groups" = "AthenaWorkgroups"
    "aws emr list-clusters --active" = "EMRClusters"
    "aws budgets describe-budgets --account-id your-account-id" = "AWSBudgets"
    "aws organizations list-accounts" = "AWSOrganizations"
    "aws waf list-web-acls" = "WAFWebACLs"
    "aws waf list-ip-sets" = "WAFIPSets"
    "aws sagemaker list-training-jobs" = "SageMakerTrainingJobs"
    "aws sagemaker list-models" = "SageMakerModels"
}

# Execute commands
foreach ($command in $commands.GetEnumerator()) {
    Execute-AWSCommand -command $command.Key -filene $command.Value
}

```


Get ec2 list per region
```
$regions = @(  
    "ap-south-1",  
    "eu-north-1",  
    "eu-west-3",  
    "eu-west-2",  
    "eu-west-1",  
    "ap-northeast-3",  
    "ap-northeast-2",  
    "ap-northeast-1",  
    "ca-central-1",  
    "sa-east-1",  
    "ap-southeast-1",  
    "ap-southeast-2",  
    "eu-central-1",  
    "us-east-1",  
    "us-east-2",  
    "us-west-1",  
    "us-west-2"  
)  
  
foreach ($region in $regions) {  
    Write-Host "EC2 instances in $region"  
    & aws ec2 describe-instances --region $region
    Write-Host ""  
}  

```