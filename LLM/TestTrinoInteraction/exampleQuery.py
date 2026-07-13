import httpx
import json
import time

url = "http://localhost:8080/v1/statement"
query = "SHOW TABLES FROM iceberg.demographics"

# httpx accepts a list of tuples — duplicate header names work fine
headers = [
    ("X-Trino-User", "Alice"),
    ("X-Trino-Catalog", "iceberg"),
    ("X-Trino-Schema", "default"),
    ("X-Trino-Extra-Credential", "department=human_resources"),
    ("X-Trino-Extra-Credential", "role=hr_manager"),
]

with httpx.Client() as client:
    # Initial POST
    response = client.post(url, headers=headers, content=query)
    response.raise_for_status()
    result = response.json()

    print("Initial response:")
    print(json.dumps(result, indent=2))

    columns = result.get("columns", [])
    all_rows = []

    if "data" in result:
        all_rows.extend(result["data"])

    next_uri = result.get("nextUri")

    while next_uri:
        time.sleep(0.3)

        response = client.get(next_uri, headers=headers)
        response.raise_for_status()
        result = response.json()

        state = result.get("stats", {}).get("state", "UNKNOWN")
        print(f"State: {state}")

        if "columns" in result and not columns:
            columns = result["columns"]

        if "data" in result:
            all_rows.extend(result["data"])
            print(f"  Got {len(result['data'])} rows (total so far: {len(all_rows)})")

        if state == "FAILED":
            error = result.get("error", {})
            raise RuntimeError(
                f"Query failed: {error.get('message')} "
                f"(code: {error.get('errorCode')})"
            )

        next_uri = result.get("nextUri")

print(f"\nDone. {len(all_rows)} total rows.")
if columns:
    print("Columns:", [c["name"] for c in columns])
for row in all_rows:
    print(row)