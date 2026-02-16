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
        ), None
    except Exception as e:
        return None, str(e)


def execute_collector(account_id, role_name, func, *args, **kwargs):
    """
    Executes a collector function.
    Explicitly passes account_id as it is required by all collectors.
    """
    try:
        return func(*args, account_id=account_id, **kwargs)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] in ['ExpiredToken', 'TokenRefreshRequired']:
            log_info(f"Session expired mid-scan for {account_id}. Refreshing session.", account_id)
            new_session = get_assumed_session(account_id, role_name)
            if not new_session:
                return [], f"Failed to refresh session"

            kwargs['session'] = new_session
            return func(*args, account_id=account_id, **kwargs)
        raise e


def scan_region_logic(session, region, account_id, role_name):
    region_results = []
    region_errors = set()

    collectors = [
        collect_ec2_instances,
        collect_ebs_volumes,
        collect_lambda_functions,
        collect_asg_as_ec2_equivalent
    ]

    for collector in collectors:
        data, error = execute_collector(
            account_id,
            role_name,
            collector,
            session=session,
            region=region
        )

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
        session, error_msg = get_assumed_session(account_id, role_name)
        if not session:
            log_warn(f"Skipping {name}: Role '{role_name}' cannot be assumed.", account_id)
            return None, [f"AssumeRole Error: {error_msg}"]

    account_results = []
    account_errors = set()

    try:
        s3_data, s3_err = collect_s3_buckets(session, account_id)
        if s3_data: account_results.extend(s3_data)
        if s3_err:
            if isinstance(s3_err, list):
                account_errors.update(s3_err)
            else:
                account_errors.add(s3_err)
    except Exception:
        pass

    available_regions, region_error = list_regions(session)
    if region_error:
        log_warn(f"Region discovery failed. Falling back to default regional list.", account_id)
        account_errors.add("ec2:DescribeRegions")

    if regions_filter:
        if region_error:
            target_regions = regions_filter
        else:
            target_regions = [r for r in available_regions if r in regions_filter]

        skipped = sorted(list(set(regions_filter) - set(target_regions)))
        if skipped:
            log_info(f"[!] Restricted: Skipping disabled regions: {', '.join(skipped)}", account_id)
    else:
        target_regions = available_regions

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(scan_region_logic, session, r, account_id, role_name) for r in target_regions]
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
    return account_results, list(account_errors)


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Documentation & Updates:
  GitHub: https://github.com/upwindsecurity/aws-resource-inventory
  Releases: https://github.com/upwindsecurity/aws-resource-inventory/releases
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
    audit_report = {}

    total_accounts = len(scan_list)
    full_success_count = 0
    partial_count = 0

    regions_list = [r.strip() for r in args.regions.split(",")] if args.regions else None
    if args.regions:
        clean_regions = ", ".join(regions_list)
        log_info(f"Target Regions: [{clean_regions}]")

    for index, acc in enumerate(scan_list, start=1):
        print("")
        progress = f"[{index}/{total_accounts}]"

        try:
            is_runner = (acc["id"] == runner_id)
            results, errors = scan_account(acc, args.role, regions_list, is_runner, progress)

            if results is None:
                audit_report[acc['id']] = errors
                partial_count += 1
                continue

            all_results.extend(results)

            if errors:
                audit_report[acc['id']] = errors
                partial_count += 1
            else:
                full_success_count += 1

        except Exception as e:
            error_msg = f"Unexpected failure: {str(e)}"
            log_warn(f"Failed to scan {acc['name']}: {error_msg}", acc['id'])
            audit_report[acc['id']] = [error_msg]
            partial_count += 1

    if len(audit_report) > 0 and len(audit_report) < 10:
        print("\n" + "=" * 60)
        log_warn("Errors report", "SYSTEM")
        print("=" * 60)
        for acc_id, issues in audit_report.items():
            unique_issues = sorted(list(set(issues)))
            print(f"\nAccount ({acc_id}):")
            for issue in unique_issues:
                print(f"  - {issue}")
        print("=" * 60 + "\n")
    elif len(audit_report) >=10:
        name_map = {acc['id']: acc['name'] for acc in scan_list}
        audit_filename = "output/audit_report.txt"

        try:
            with open(audit_filename, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write(f"Errors Report: \n")
                f.write("=" * 80 + "\n\n")

                for acc_id, issues in audit_report.items():
                    acc_name = name_map.get(acc_id, "Unknown Account")
                    f.write(f"Account: {acc_name} ({acc_id})\n")
                    for issue in sorted(list(set(issues))):
                        f.write(f"  [X] {issue}\n")
                    f.write("-" * 40 + "\n")

            print("")
            log_info(f"Detailed audit report saved to → {audit_filename}", "SYSTEM")
        except Exception as e:
            log_warn(f"Failed to write audit file: {str(e)}", "SYSTEM")

    log_info(
        f"Summary: {full_success_count} full scans, {partial_count} partial/failed scans out of {total_accounts} total.",
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