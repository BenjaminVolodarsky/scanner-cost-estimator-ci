import boto3
from botocore.config import Config

def get_aws_config():
    """Returns a boto3 config with adaptive retries to handle throttling."""
    return Config(
        retries={
            'max_attempts': 10,
            'mode': 'adaptive'
        }
    )

def get_client(session, service, region_name=None):
    """
    Helper to create a client with the standard config.
    Renamed 'region' to 'region_name' to match boto3 standards.
    """
    return session.client(service, region_name=region_name, config=get_aws_config())