import boto3


def list_regions(session=None):
    client = session.client('ec2', region_name='us-east-1') if session else boto3.client('ec2')
    default_regions = ['ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-north-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'sa-east-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']
    try:
        response = client.describe_regions(
            AllRegions=False,
            Filters=[{
                'Name': 'opt-in-status',
                'Values': ['opt-in-not-required', 'opted-in']
            }]
        )
        return [r['RegionName'] for r in response['Regions']], None
    except Exception as e:
        return default_regions, e


