# AWS Workload Cost Estimator

This tool estimates the amount of scannable AWS resources in an organization.
The results can later be used for cost prediction and capacity planning.

- Read-Only: All API calls are non-mutating and do not modify any resources.
- AWS Native: No API calls are made outside of the AWS environment.
- Execution is recommended via a [dedicated Permission Boundary]() to ensure the principle of least privilege.

More about required roles and policies can be found in the [Permissions](#least-privilege-permission-boundary-recommended) section.

---

## Table of Contents
- [Prerequisites](#prerequisites)
- [Permissions](#permissions)
- [Installation](#installation)
- [Usage](#usage)
- [Flags](#flags)
---

## Prerequisites

*Dependencies are pre-installed on AWS CloudShell. For local execution, ensure:*

- Python 3.9+
- Boto3 (pip install boto3)
- AWS Credentials configured for the runner identity.

---

## Permissions

#### The script uses a cross-account IAM role to scan member accounts. By default, it looks for the OrganizationAccountAccessRole, but this can be customized via [flags](#flags).
- More details regarding the default **cross-account role** and accessing member accounts in an organization can be found here:
[Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access.html).

**Required permissions for the cross-account role:**

| Service | Permission                  | Action                                                                                                                                                                                            |
| :--- |:----------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **EC2** | `DescribeInstances`         | <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html" target="_blank">DescribeInstances</a>
| **EC2** | `DescribeVolumes`           | <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html" target="_blank">DescribeVolumes</a>                                                                                                |
| **EC2** | `DescribeRegions`           | <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html" target="_blank">DescribeRegions</a>                                                                                               |
| **Auto Scaling** | `DescribeAutoScalingGroups` | <a href="https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_DescribeAutoScalingGroups.html" target="_blank">DescribeAutoScalingGroups</a>                                                                     |
| **Lambda** | `ListFunctions`             | <a href="https://docs.aws.amazon.com/lambda/latest/api/API_ListFunctions.html" target="_blank">ListFunctions</a>                                                                                                          |
| **S3** | `ListAllMyBuckets`          | <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html" target="_blank">ListBuckets</a>                                                                                                               |
| **S3** | `GetBucketLocation`         | <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html" target="_blank">HeadBucket</a>                                                                                                                |
| **CloudWatch** | `GetMetricData`             | <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricData.html" target="_blank">GetMetricData</a>                                                                                       |


Notice: in order to perform a full multi-account scan, the runner account (management account or a member account that is a delegated administrator) must have the following permissions:
- organizations:ListAccounts [ListAccounts](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html)
- sts:AssumeRole [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
### Least Privilege Permission Boundary (Recommended)

We highly recommend running the script with a Permission Boundary attached to the **cross-account role**.
You can use an AWS managed policy or a customer managed policy to set the boundary for an IAM entity (user or role). That policy limits the maximum permissions for the user or role.
You can attach this policy to the role you choose to run the script with. In order to create the policy:

#### 1. Create an IAM Policy with the defined permissions ceiling (you can use the example JSON below).

#### 2. In the IAM Console, under Roles tab, choose the role you want to attach the policy to, and attach it under the "Permissions boundary" tab.

**Example Policy JSON:**

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowCostEstimationMetadataOnly",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeVolumes",
                "ec2:DescribeRegions",
                "autoscaling:DescribeAutoScalingGroups",
                "lambda:ListFunctions",
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "cloudwatch:GetMetricData"
            ],
            "Resource": "*"
        }
    ]
}
```

# Installation

```bash
git clone https://github.com/BenjaminVolodarsky/scanner-cost-estimator-dev.git
cd scanner-cost-estimator-dev
```
* If boto3 is not already installed (e.g. outside CloudShell):
```bash
pip install boto3
```

# Usage
#### You can use the script in two ways:
### 1. Cross-account scan:

```bash
./upwind
```
* The tool can perform a cross-account scan by running the script without any arguments. The script will use the default cross-account role name (OrganizationAccountAccessRole) to scan all active member accounts in the organization.
* The tool will inform that it is performing a cross-account scan, and print the amount of accounts it is revealed.
* The tool will scan all active member accounts in the organization, and will print permission exceptions if any.
* The tool will produce a JSON file containing the data about the resources it collected from each account.

*Cross-account scan is only available if the runner account is a management account or a member account that is a delegated administrator. If the tool wouldn't be able to perform 
[ListAccounts](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html), it will automatically switch to the local account scan option, and scan only the account it been executed from.*
### 2. Local account scan:
```bash
./upwind
```
* The tool will perform a local scan by running the script without any arguments. The script will switch to local scan as it won't be able to perform 
[ListAccounts](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html).
  * Notice: if the runner account is a management account or a member account that is a delegated administrator, the tool will perform a cross-account scan. If you are willing to perform a local scan on member/administrator accounts, you **must** use the --accounts flag.
* The tool will inform you that Organization access unavailable (single-account scan)
* The tool will produce a JSON file containing the data about the resources it collected from the local account.

### 3. Manual accounts scan:
```bash
./upwind --accounts <account_id>
```

* You can perform a multi-account scan even from a member account by using the --accounts flag. This flag bypasses the 
[ListAccounts](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html) call, and only scans the account you specified.
* The tool will produce a JSON file containing the data about the resources it collected from the accounts you specified.

*The runner account don't have to be a management account,
but it still has to have the sts:AssumeRole [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) 
permission to perform the scan.*

*A trust relationship must be configured on the target role , granting the runner account permission to assume the role via sts:AssumeRole.*

## Flags:
### You can use the following flags to customize the scan:
### --accounts <account_id>
* You can use this flag to specify a list of accounts to scan.
* It will bypass the Cross-account scan and will not perform a
[ListAccounts](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html) call. Instead, it will perform a Local account scan (if you only specify the runner account in the list), or a Manual accounts scan (using sts:assumeRole). 
* The runner account in this mode wouldn't be scanned without being specified in the list.
```bash
./upwind --accounts <account_id1>,<account_id2>
```
### --role <role_name>
This flag allows you to specify a role to assume in the target accounts. It would not be used on Local account scan. 
```bash
./upwind --role <role_name>
```

### --region <region>
This flag allows you to specify a list of regions to scan (on all the accounts). 
```bash
./upwind --region us-east-1,eu-west-1
```

