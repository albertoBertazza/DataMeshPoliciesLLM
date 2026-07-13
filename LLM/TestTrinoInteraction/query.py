"""
trino_identity_queries.py
--------------------------
Runs SQL queries against Trino using different Identity configurations.
"""

import requests
import json
import time
import argparse
import sys
from dataclasses import dataclass, field
from typing import Optional


# ============================================================
# Identity Model
# ============================================================

@dataclass
class TrinoIdentity:
    user: str
    catalog: str = "system"
    schema: str = "runtime"
    groups: list = field(default_factory=list)
    principal: Optional[str] = None
    enabled_roles: list = field(default_factory=list)
    catalog_roles: dict = field(default_factory=dict)
    extra_credentials: dict = field(default_factory=dict)
    client_info: Optional[str] = None

    def to_headers(self) -> dict:
        headers = {
            "X-Trino-User": self.user,
            "X-Trino-Catalog": self.catalog,
            "X-Trino-Schema": self.schema,
        }

        # -------------------------
        # Roles
        # -------------------------
        role_parts = []

        for r in self.enabled_roles:
            role_parts.append(f"system={r}")

        for cat, role in self.catalog_roles.items():
            role_parts.append(f"catalog={cat}:{role}")

        if role_parts:
            headers["X-Trino-Role"] = ",".join(role_parts)

        # -------------------------
        # Extra credentials (OPA input source)
        # -------------------------
        cred_parts = {}

        if self.groups:
            cred_parts["groups"] = ",".join(self.groups)

        for k, v in self.extra_credentials.items():
            cred_parts[k] = str(v)

        if cred_parts:
            headers["X-Trino-Extra-Credential"] = ",".join(
                f"{k}={v}" for k, v in cred_parts.items()
            )

        # -------------------------
        # Client info
        # -------------------------
        if self.client_info:
            headers["X-Trino-Client-Info"] = self.client_info

        return headers

    def __str__(self) -> str:
        return (
            f"TrinoIdentity(user={self.user}, "
            f"groups={self.groups}, "
            f"roles={self.enabled_roles}, "
            f"catalog_roles={self.catalog_roles}, "
            f"extra_credentials={self.extra_credentials})"
        )


# ============================================================
# Predefined identities
# ============================================================

IDENTITIES = {
    "admin": TrinoIdentity(
        user="trino",
        catalog="iceberg",
        schema="hr",
        enabled_roles=["ALL"],
        extra_credentials={"role": "admin", "age": "40"},
    ),

    "analyst": TrinoIdentity(
        user="alice_analyst",
        catalog="iceberg",
        schema="hr",
        extra_credentials={"role": "manager", "age": "25"},
    ),

    "service": TrinoIdentity(
        user="etl_pipeline",
        catalog="iceberg",
        schema="mobility",
        extra_credentials={"role": "service", "age": "99"},
    ),

    "guest": TrinoIdentity(
        user="guest",
        catalog="iceberg",
        schema="hr",
        extra_credentials={"role": "guest", "age": "30"},
    ),

    "underage": TrinoIdentity(
        user="young_user",
        catalog="iceberg",
        schema="hr",
        extra_credentials={"role": "manager", "age": "15"},
    ),
}


IDENTITY_QUERIES = {
    "admin": [
        "SHOW SCHEMAS FROM iceberg",
        "SHOW TABLES FROM iceberg.hr",
        "SELECT * FROM iceberg.hr.employees LIMIT 5",
    ],
    "analyst": [
        "SHOW SCHEMAS FROM iceberg",
        "SELECT * FROM iceberg.hr.employees LIMIT 5",
    ],
    "service": [
        "SELECT count(*) FROM iceberg.mobility.taxi_trips",
    ],
    "guest": [
        "SHOW TABLES FROM iceberg.hr",
    ],
    "underage": [
        "SELECT * FROM iceberg.hr.employees LIMIT 5",
    ],
}


# ============================================================
# Query execution
# ============================================================

def run_query(base_url, identity, sql, verbose=True):
    headers = identity.to_headers()
    url = f"{base_url.rstrip('/')}/v1/statement"

    if verbose:
        print("\n------------------------------")
        print(f"Identity: {identity}")
        print(f"SQL: {sql}")
        print("------------------------------")
        print(json.dumps(headers, indent=2))

    try:
        resp = requests.post(url, headers=headers, data=sql.encode(), timeout=10)
    except Exception as e:
        return {"state": "CONNECTION_ERROR", "error": str(e)}

    try:
        data = resp.json()
    except Exception:
        return {
            "state": "BAD_RESPONSE",
            "error": resp.text,
            "status": resp.status_code,
        }

    if resp.status_code != 200:
        return {
            "state": "HTTP_ERROR",
            "error": data,
            "status": resp.status_code,
        }

    query_id = data.get("id")
    next_uri = data.get("nextUri")

    polls = 0

    while next_uri and polls < 60:
        polls += 1
        time.sleep(0.3)

        try:
            r = requests.get(next_uri, headers=headers, timeout=10)
            data = r.json()
        except Exception as e:
            return {"state": "POLL_ERROR", "error": str(e)}

        stats = data.get("stats") or {}
        state = stats.get("state", "UNKNOWN")

        if "error" in data:
            return {
                "state": "FAILED",
                "query_id": query_id,
                "error": data["error"].get("message"),
            }

        if state == "FAILED":
            err = data.get("error", {})
            return {
                "state": "FAILED",
                "query_id": query_id,
                "error": err.get("message"),
            }

        if state == "FINISHED":
            return {
                "state": "FINISHED",
                "query_id": query_id,
                "columns": [c["name"] for c in data.get("columns", [])],
                "rows": data.get("data", []),
            }

        next_uri = data.get("nextUri")

    return {"state": "TIMEOUT", "query_id": query_id}


# ============================================================
# Runner
# ============================================================

def run_all(base_url):
    for name, identity in IDENTITIES.items():
        print("\n==============================")
        print(f"IDENTITY: {name}")
        print("==============================")

        for sql in IDENTITY_QUERIES.get(name, []):
            result = run_query(base_url, identity, sql)
            print_result(result)


def run_single(base_url, identity_name, sql):
    identity = IDENTITIES[identity_name]
    result = run_query(base_url, identity, sql)
    print_result(result)


def print_result(result):
    state = result.get("state")

    if state == "FINISHED":
        print(f"✓ OK ({len(result.get('rows', []))} rows)")
        for r in result.get("rows", [])[:10]:
            print(r)

    else:
        print(f"✗ {state}")
        print(result)


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--identity", choices=list(IDENTITIES.keys()))
    parser.add_argument("--sql")
    parser.add_argument("--quiet", action="store_true")

    args = parser.parse_args()

    if args.identity:
        sql = args.sql or IDENTITY_QUERIES[args.identity][0]
        run_single(args.url, args.identity, sql)
    else:
        if args.sql:
            print("--sql requires --identity")
            sys.exit(1)
        run_all(args.url)