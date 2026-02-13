import json
import csv
import os


def write_output(data, json_filename="output.json", csv_filename="output.csv"):
    os.makedirs("output", exist_ok=True)

    with open(f"output/{json_filename}", "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\n JSON saved → output/{json_filename}")

    if not data:
        print("⚠No data collected; skipping CSV generation.")
        return

    keys = set()
    for row in data:
        keys.update(row.keys())

    fieldnames = sorted(list(keys))
    prioritized = ["account_id", "resource", "region"]
    for col in reversed(prioritized):
        if col in fieldnames:
            fieldnames.insert(0, fieldnames.pop(fieldnames.index(col)))

    sorted_data = sorted(
        data,
        key=lambda r: (
            str(r.get("resource", "")),
            str(r.get("account_id", "")),
            str(r.get("region", "")),
            json.dumps(r, sort_keys=True, default=str),
        ),
    )

    with open(f"output/{csv_filename}", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sorted_data)

    print(f"\n CSV saved  → output/{csv_filename}")