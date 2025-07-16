
IAM permissions
To find the public IPs from all AWS services, the minimal policy needed by your IAM user is:

```
IAM permissions
To find the public IPs from all AWS services, the minimal policy needed by your IAM user is:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "apigateway:GET",
        "cloudfront:ListDistributions",
        "ec2:DescribeInstances",
        "elasticloadbalancing:DescribeLoadBalancers",
        "lightsail:GetInstances",
        "lightsail:GetLoadBalancers",
        "rds:DescribeDBInstances",
        "redshift:DescribeClusters",
        "es:ListDomainnes"
      ],
      "Resource": "*"
    }
  ]
}
```

get all ips
https://github.com/arkadiyt/aws_public_ips

