from datetime import datetime, timedelta
import logging
import botocore
from utils.config_helper import get_client

logger = logging.getLogger("CloudScanner")

def collect_s3_buckets(session, account_id="unknown"):
    s3 = get_client(session, "s3")
    results = []
    error = None
    buckets_by_region = {}
    skipped_buckets = []
    fetched_count = 0

    try:
        paginator = s3.get_paginator('list_buckets')
        now = datetime.utcnow()
        start_time = now - timedelta(days=2)

        for page in paginator.paginate():
            for b in page.get("Buckets", []):
                name = b["Name"]
                region = None

                try:
                    response = s3.head_bucket(Bucket=name)
                    region = response.get('ResponseMetadata', {}).get('HTTPHeaders', {}).get('x-amz-bucket-region')
                except botocore.exceptions.ClientError as e:
                    region = e.response.get('Error', {}).get('Region') or \
                             e.response.get('ResponseMetadata', {}).get('HTTPHeaders', {}).get('x-amz-bucket-region')

                if region:
                    fetched_count += 1
                    if region == "EU": region = "eu-west-1"
                    if region not in buckets_by_region:
                        buckets_by_region[region] = []
                    buckets_by_region[region].append(name)
                else:
                    skipped_buckets.append(name)

        if skipped_buckets:
            logger.info(
                f"s3:HeadBucket failed to resolve {len(skipped_buckets)} regions (Fetched: {fetched_count}). "
                f"Action required: add 's3:ListBucket' permission.",
                extra={'account_id': account_id}
            )
            error = "s3:ListBucket"

        for region, bucket_names in buckets_by_region.items():
            cw = get_client(session, "cloudwatch", region_name=region)
            chunk_size = 250

            for i in range(0, len(bucket_names), chunk_size):
                chunk = bucket_names[i:i + chunk_size]
                queries = []
                for idx, b_name in enumerate(chunk):
                    queries.append({
                        'Id': f'size_{idx}',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/S3',
                                'MetricName': 'BucketSizeBytes',
                                'Dimensions': [
                                    {'Name': 'BucketName', 'Value': b_name},
                                    {'Name': 'StorageType', 'Value': 'StandardStorage'}
                                ]
                            },
                            'Period': 86400,
                            'Stat': 'Average'
                        },
                        'Label': f"{b_name}|size"
                    })
                    queries.append({
                        'Id': f'count_{idx}',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/S3',
                                'MetricName': 'NumberOfObjects',
                                'Dimensions': [
                                    {'Name': 'BucketName', 'Value': b_name},
                                    {'Name': 'StorageType', 'Value': 'AllStorageTypes'}
                                ]
                            },
                            'Period': 86400,
                            'Stat': 'Average'
                        },
                        'Label': f"{b_name}|count"
                    })

                try:
                    response = cw.get_metric_data(MetricDataQueries=queries, StartTime=start_time, EndTime=now)
                    metrics_map = {res['Label']: (res['Values'][0] if res['Values'] else 0) for res in
                                   response['MetricDataResults']}

                    for b_name in chunk:
                        results.append({
                            "account_id": account_id,
                            "resource": "s3_bucket",
                            "region": region,
                            "bucket_size_gb": round(metrics_map.get(f"{b_name}|size", 0) / (1024 ** 3), 2),
                            "bucket_doc_num": int(metrics_map.get(f"{b_name}|count", 0))
                        })
                except Exception as e:
                    if "AccessDenied" in str(e):
                        error = "cloudwatch:GetMetricData"
                    for b_name in chunk:
                        results.append(
                            {"account_id": account_id, "resource": "s3_bucket", "region": region, "bucket_size_gb": 0,
                             "bucket_doc_num": 0})

        for b_name in skipped_buckets:
            results.append({
                "account_id": account_id,
                "resource": "s3_bucket",
                "region": "Unknown",
                "bucket_size_gb": 0,
                "bucket_doc_num": 0
            })

    except Exception as e:
        if "AccessDenied" in str(e):
            error = "s3:ListAllMyBuckets"  # Actionable feedback for customer
        else:
            error = str(e)

    return results, error