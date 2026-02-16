from utils.config_helper import get_client


def collect_asg_as_ec2_equivalent(session, region, account_id):
    client = get_client(session, "autoscaling", region_name=region)
    results = []
    error = None
    try:
        paginator = client.get_paginator('describe_auto_scaling_groups')
        for page in paginator.paginate():
            for asg in page['AutoScalingGroups']:
                if asg.get('DesiredCapacity', 0) == 0:
                    continue

                asg_tags = {t['Key'].lower(): str(t.get('Value', '')).lower() for t in asg.get('Tags', [])}

                k8s_markers = ['eks', 'k8s', 'kubernetes', 'cluster-autoscaler']

                is_k8s = any(marker in str(asg_tags) for marker in k8s_markers) or \
                         any('k8s.io' in key or 'kubernetes.io' in key for key in asg_tags.keys())

                if is_k8s:
                    continue

                results.append({
                    "account_id": account_id,
                    "resource": "asg_ec2_equivalent",
                    "region": region,
                    "asg_instance_count": asg.get('DesiredCapacity')
                })
    except Exception as e:
        if "AccessDenied" in str(e):
            error = "autoscaling:DescribeAutoScalingGroups"
    return results, error