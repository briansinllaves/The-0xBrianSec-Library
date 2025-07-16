Set-AWSCredential -AccessKey Apanda5ZF3 -SecretKey XJPsssss0t0aVOg

aws ec2 describe-instances

#!/bin/bash

# Script to describe all running EC2 instances

aws ec2 describe-instances --query 'Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,State:State.ne}' --output table