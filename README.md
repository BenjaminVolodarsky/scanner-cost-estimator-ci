# aws-resource-inventory

This tool inventories scannable AWS resources across an organization.

d

- Read-Only: All API calls are non-mutating and do not modify any resources.
- AWS Native: No API calls are made outside of the AWS environment.
- Execution is recommended via a [dedicated Permission Boundary](#least-privilege-permission-boundary-recommended) to ensure the principle of least privilege.
- The tool performs metadata discovery through AWS control-plane APIs only.

More details about required roles and policies can be found in the [Permissions](#permissions) section.

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
- AWS credentials configured for the runner identity.

---

## Permissions

The script uses a cross-account IAM role to scan member accounts.
By default, it looks for `OrganizationAccountAccessRole`, but this can be customized via [flags](#flags).
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
| **S3** | `ListBucket`                | <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html" target="_blank">HeadBucket</a>                                                                                                                |
| **CloudWatch** | `GetMetricData`             | <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricData.html" target="_blank">GetMetricData</a>                                                                                       |


To perform a full multi-account scan, the runner account (management account or a member account that is a delegated administrator) must have the following permissions:
- organizations:ListAccounts [ListAccounts](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html)
- sts:AssumeRole [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
### Least Privilege Permission Boundary (Recommended)

We strongly recommend attaching a Permission Boundary to the execution role.

A permission boundary defines the maximum allowed permissions, regardless of other policies attached to the role.
This ensures the script remains read-only even if broader permissions are later granted.

You may use either an AWS-managed or a customer-managed policy.

### Implementation Steps
#### 1. Create an IAM policy that defines the permissions ceiling (example below).

#### 2. In the IAM Console → Roles → select the execution role → attach the policy under Permissions boundary.

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
                "s3:ListBucket",
                "cloudwatch:GetMetricData"
            ],
            "Resource": "*"
        }
    ]
}
```

# Installation

```bash
git clone https://github.com/upwindsecurity/aws-resource-inventory.git
cd aws-resource-inventory
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
Runs automatically when executed without arguments.
* Uses the default role `OrganizationAccountAccessRole`.
* Displays the number of accounts discovered.
* Reports permission failures per account.
* Produces a JSON output file with collected resources.

* If the runner cannot call `organizations:ListAccounts`, the tool falls back to a local scan.

### 2. Local account scan:
```bash
./upwind
```
Runs when organization access is unavailable.
* Scans only the account where the tool is executed.
* Produces a JSON file with the collected resources.
* If the runner is a management or delegated administrator account, cross-account scan will run by default.
To force local behavior, use the `--accounts` flag.

### 3. Manual accounts scan:
```bash
./upwind --accounts <account_id>
```
Allows scanning specific accounts from any runner.
* Bypasses the ListAccounts API.
* Only the specified accounts are scanned.
* **The runner account is scanned only if included in the list.**
* Produces a JSON file with the collected resources.

## Flags:
### You can use the following flags to customize the scan:
### --accounts <id1,id2,...>
Specify which accounts should be scanned.
* Skips organization discovery.
* The runner account will not be scanned unless explicitly listed.

Example:
```bash
./upwind --accounts 111111111111,222222222222
```
### --role <role_name>
Specify a custom role name to assume in target accounts.
Not used during a local account scan. 
```bash
./upwind --role MyCustomRole
```

### --region <region1,region2,...>
Specify which regions should be scanned across the selected accounts. 
* Disabled regions are skipped.
* Even if `ec2:DescribeRegions` is unavailable, the explicitly provided regions are still scanned.
```bash
./upwind --region us-east-1,eu-west-1
```

## Versioning

We use [Semantic Versioning](https://semver.org/) for releases. For the versions
available, see the [tags on this repository](https://github.com/upwindsecurity/aws-resource-inventory/tags).

## Troubleshooting:
**_If runtime exceptions are detected in more than 10 accounts, a file named:_**
**_audit_report.txt_** will be generated.

### Missing `lambda:ListFunctions`
  * Affects: Lambda functions will not be collected.
  * Solution: Grant
    * `lambda:ListFunctions`

### Missing `autoscaling:DescribeAutoScalingGroups`
  * Affects: Auto Scaling groups will not be collected.
    * _Note: since the tool excludes EC2 instances tagged with AutoScalingGroup, those instances will be absent from the report._
  * Solution: Grant
    * `autoscaling:DescribeAutoScalingGroups`

### Missing `ec2:DescribeInstances`
  * Affects: EC2 instances will not be collected.
  * Solution: Grant
    * `ec2:DescribeInstances`
### Missing `ec2:DescribeRegions`
  * Affects: Region discovery may be incomplete.
  * If a region is not an AWS default region and not provided via --region, it will be skipped. [Docs](https://docs.aws.amazon.com/controltower/latest/userguide/opt-in-region-considerations.html)
  * Solution: Grant
    * `ec2:DescribeRegions`
### Missing `ec2:DescribeVolumes`
  * Affects: EBS volumes will not be collected.
  * Solution: Grant
    * `ec2:DescribeVolumes`
### Missing `s3:ListAllMyBuckets`
  * Affects: S3 buckets will not be collected.
  * Solution: Grant
    * `s3:ListAllMyBuckets`
### Missing `s3:ListBucket`
  * Affects: If HeadBucket fails, the tool attempts to infer the region from the error response. If that also fails, the bucket is marked as unknown region, and related metrics are skipped.
  * Solution: Grant
    * `s3:ListBucket`