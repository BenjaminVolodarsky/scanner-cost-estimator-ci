from utils.config_helper import get_client

def collect_lambda_functions(session, region, account_id):
    client = get_client(session, "lambda", region_name=region)
    results = []
    error = None
    try:
        paginator = client.get_paginator('list_functions')
        for page in paginator.paginate():
            for func in page['Functions']:
                results.append({
                    "account_id": account_id,
                    "resource": "lambda",
                    "region": region,
                    "function_memory_mb": func.get('MemorySize')
                })
    except Exception as e:
        if "AccessDenied" in str(e):
            error = "lambda:ListFunctions"
    return results, error