from utils.config_helper import get_client

def collect_ebs_volumes(session, region, account_id):
    client = get_client(session, "ec2", region_name=region)
    results = []
    error = None
    try:
        paginator = client.get_paginator('describe_volumes')
        for page in paginator.paginate():
            for vol in page['Volumes']:
                results.append({
                    "account_id": account_id,
                    "resource": "ebs",
                    "region": region,
                    "ebs_state": vol['State'],
                    "ebs_size_gb": vol['Size'],
                    "ebs_type": vol['VolumeType']
                })
    except Exception as e:
        if any(err in str(e) for err in ["AccessDenied", "UnauthorizedOperation"]):
            error = "ec2:DescribeVolumes"
    return results, error