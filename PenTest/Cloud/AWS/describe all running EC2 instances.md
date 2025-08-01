Set-AWSCredential -AccessKey Apanda -SecretKey XVOg

aws ec2 describe-instances

#!/bin/bash

# Script to describe all running EC2 instances

aws ec2 describe-instances --query 'Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,State:State.ne}' --output table