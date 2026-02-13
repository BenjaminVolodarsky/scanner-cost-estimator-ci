from utils.config_helper import get_client

def collect_ec2_instances(session, region, account_id):
    client = get_client(session, "ec2", region_name=region)
    results = []
    error = None
    try:
        paginator = client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] != 'running':
                        continue

                    tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}

                    if 'aws:autoscaling:groupName' in tags:
                        continue

                    if any(k in str(tags).lower() for k in ['eks', 'k8s', 'kubernetes']):
                        continue

                    results.append({
                        "account_id": account_id,
                        "resource": "ec2",
                        "region": region,
                        "instance_type": instance['InstanceType'],
                    })
    except Exception as e:
        if any(err in str(e) for err in ["AccessDenied", "UnauthorizedOperation"]):
            error = "ec2:DescribeInstances"
    return results, error