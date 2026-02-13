import warnings
warnings.filterwarnings("ignore", message=".*Boto3 will no longer support Python 3.9.*")
warnings.filterwarnings("ignore", category=DeprecationWarning)
import logging
import sys
import argparse
import boto3
import botocore.exceptions
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.regions import list_regions
from output.writer import write_output

from collectors.ec2 import collect_ec2_instances
from collectors.ebs import collect_ebs_volumes
from collectors.s3 import collect_s3_buckets
from collectors.lambda_functions import collect_lambda_functions
from collectors.asgConverter import collect_asg_as_ec2_equivalent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(account_id)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("CloudScanner")
logger.setLevel(logging.INFO)


def log_info(msg, account_id="SYSTEM"):
    logger.info(msg, extra={'account_id': account_id})

def log_warn(msg, account_id="SYSTEM"):
    logger.warning(msg, extra={'account_id': account_id})

def get_accounts():
    try:
        org = boto3.client("organizations")
        accounts = []
        paginator = org.get_paginator("list_accounts")
        for page in paginator.paginate():
            for acc in page.get("Accounts", []):
                state = acc.get("State") or acc.get("Status")
                if state == "ACTIVE":
                    accounts.append({"id": acc["Id"], "name": acc["Name"]})
        return accounts
    except Exception:
        return None


def get_assumed_session(account_id, role_name):
    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        response = sts.assume_role(RoleArn=role_arn, RoleSessionName="Scanner")
        creds = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    except Exception as e:
        log_warn(f"AssumeRole failed for {role_arn}: {str(e)}", account_id)
        return None


def scan_region_logic(session, region, account_id):
    region_results = []
    region_errors = set()

    collectors = [
        collect_ec2_instances,
        collect_ebs_volumes,
        collect_lambda_functions,
        collect_asg_as_ec2_equivalent
    ]

    for collector in collectors:
        data, error = collector(session, region, account_id)
        if data:
            region_results.extend(data)
        if error:
            region_errors.add(error)

    return region_results, list(region_errors)


def scan_account(account_info, role_name, regions_filter, is_runner_node, progress_prefix):
    account_id = account_info["id"]
    name = account_info["name"]
    suffix = " [Runner Account]" if is_runner_node else ""

    log_info(f"{progress_prefix} Starting scan for: {name} ({account_id}){suffix}", account_id)

    if is_runner_node:
        session = boto3.Session()
    else:
        session = get_assumed_session(account_id, role_name)
        if not session:
            log_warn(f"Skipping {name}: Role '{role_name}' cannot be assumed.", account_id)
            return []

    account_results = []
    account_errors = set()

    try:
        s3_data, s3_err = collect_s3_buckets(session, account_id)
        if s3_data: account_results.extend(s3_data)
        if s3_err: account_errors.add(s3_err)
    except Exception:
        pass

    available_regions = list_regions(session)

    if regions_filter:
        target_regions = [r for r in available_regions if r in regions_filter]
        if len(target_regions) < len(regions_filter):
            skipped = set(regions_filter) - set(target_regions)
            log_info(f"Skipping requested regions not enabled in this account: {', '.join(skipped)}", account_id)
    else:
        target_regions = available_regions

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(scan_region_logic, session, r, account_id) for r in target_regions]
        for f in as_completed(futures):
            r_data, r_errors = f.result()
            if r_data:
                account_results.extend(r_data)
            if r_errors:
                account_errors.update(r_errors)

    if account_errors:
        formatted_errors = ", ".join(sorted(account_errors))
        log_warn(f"Partial scan. Missing permissions: {formatted_errors}", account_id)

    log_info(f"Scan complete. Found {len(account_results)} resources.", account_id)
    return account_results


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Documentation & Updates:
  GitHub: https://github.com/BenjaminVolodarsky/scanner-cost-estimator-ci
  Releases: https://github.com/BenjaminVolodarsky/scanner-cost-estimator-ci/releases
        """
    )
    parser.add_argument("--role", type=str, default="OrganizationAccountAccessRole",
                        help="IAM Role for member accounts.")
    parser.add_argument("--accounts", type=str, help="Comma-separated account IDs to scan.")
    parser.add_argument("--regions", type=str, help="Comma-separated regions to scan.")
    args = parser.parse_args()

    sts = boto3.client("sts")
    runner_id = sts.get_caller_identity()["Account"]

    if args.accounts:
        ids = [x.strip() for x in args.accounts.split(",") if x.strip()]
        scan_list = [{"id": aid, "name": f"Manual-{aid}"} for aid in ids]
        log_info(f"Execution Mode: Manual accounts scan ({len(scan_list)} accounts)")
    else:
        accounts = get_accounts()
        if accounts:
            log_info(f"Execution Mode: Cross-account scan ({len(accounts)} accounts)")
            scan_list = accounts
        else:
            log_info("Execution Mode: Local account scan (Organization discovery unavailable)")
            scan_list = [{"id": runner_id, "name": "Local-Account"}]

    all_results = []
    total_accounts = len(scan_list)
    full_success_count = 0
    partial_count = 0

    for index, acc in enumerate(scan_list, start=1):
        print("")  # Visual separator
        progress = f"[{index}/{total_accounts}]"

        try:
            is_runner = (acc["id"] == runner_id)
            results = scan_account(acc, args.role, None, is_runner, progress)
            all_results.extend(results)

            if len(results) == 0:
                partial_count += 1
            else:
                full_success_count += 1
        except Exception as e:
            log_warn(f"Failed to scan {acc['name']}: {str(e)}", acc['id'])

    print("")
    log_info(f"Summary: {full_success_count} full scans, {partial_count} partial scans out of {total_accounts} total.",
             "SYSTEM")
    write_output(all_results)


def run():
    try:
        main()
    except botocore.exceptions.NoCredentialsError:
        print(f"\n[!] Error: AWS credentials not found.")
        print(f"Please run: 'aws sso login' or 'aws configure'")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\r\n[!] Execution cancelled by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected Error:{e}")
        sys.exit(1)


if __name__ == "__main__":
    run()