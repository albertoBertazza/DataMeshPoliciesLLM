import json
import statistics
import time
from pathlib import Path

import requests


# ============================================================================
# Config
# ============================================================================

OPA_URL = "http://localhost:8182"

DECISION_PATH = "/v1/data/trino/authz/allow"


# ============================================================================
# Build OPA input
# ============================================================================

def build_opa_input(test):
    """
    Convert the generated benchmark test into the input structure expected
    by the OPA policy.
    """

    test_input = test["input"]

    username = test_input.get("username")

    catalog = test_input.get("catalog")
    schema = test_input.get("schema")
    table = test_input.get("table")

    action = test_input.get("action")

    # ------------------------------------------------------------------------
    # Security group
    # ------------------------------------------------------------------------

    security_group = test.get("security_group")

    groups = []

    if security_group:
        groups.append(security_group)

    # ------------------------------------------------------------------------
    # Build resources
    # ------------------------------------------------------------------------

    schema_resource = {
        "catalogName": catalog,
        "schemaName": schema
    }

    table_resource = {
        "catalogName": catalog,
        "schemaName": schema,
        "tableName": table
    }

    column_resource = {
        "catalogName": catalog,
        "schemaName": schema,
        "tableName": table,
        "columnName": ""
    }

    # ------------------------------------------------------------------------
    # Filter resources
    # ------------------------------------------------------------------------

    filter_resources = test_input.get(
        "filterResources",
        []
    ) or []

    # ------------------------------------------------------------------------
    # Final OPA input
    # ------------------------------------------------------------------------

    return {
        "context": {
            "identity": {
                "user": username,
                "groups": groups
            }
        },

        "action": {
            "operation": action,

            "resource": {
                "schema": schema_resource,
                "table": table_resource,
                "column": column_resource,
                "filterResources": filter_resources
            }
        }
    }


# ============================================================================
# Single OPA test
# ============================================================================

def run_test(test):

    url = OPA_URL + DECISION_PATH

    # ------------------------------------------------------------------------
    # Build OPA input
    # ------------------------------------------------------------------------

    opa_input = build_opa_input(test)

    # ------------------------------------------------------------------------
    # Measure complete HTTP request
    # ------------------------------------------------------------------------

    start = time.perf_counter_ns()

    response = requests.post(
        url,
        params={
            "metrics": "true"
        },
        json={
            "input": opa_input
        },
        timeout=30
    )

    elapsed = time.perf_counter_ns() - start

    response.raise_for_status()

    data = response.json()

    metrics = data.get(
        "metrics",
        {}
    )

    # ------------------------------------------------------------------------
    # Validate OPA response
    # ------------------------------------------------------------------------

    if "result" not in data:

        raise RuntimeError(
            "OPA did not return a decision.\n"
            f"URL: {url}\n"
            f"Test: {test.get('id')}\n"
            f"Permission: {test.get('permission')}\n"
            f"OPA input:\n"
            f"{json.dumps(opa_input, indent=4)}\n"
            f"Response:\n"
            f"{json.dumps(data, indent=4)}"
        )

    # ------------------------------------------------------------------------
    # Preserve EXACT OPA result
    # ------------------------------------------------------------------------

    opa_actual = data["result"]

    # ------------------------------------------------------------------------
    # Return result
    # ------------------------------------------------------------------------

    return {

        # --------------------------------------------------------------------
        # Status
        # --------------------------------------------------------------------

        "status": "EXECUTED",

        "skipped": False,

        # --------------------------------------------------------------------
        # Identity
        # --------------------------------------------------------------------

        "id":
            test["id"],

        "trino_test_id":
            test.get("trino_test_id"),

        # --------------------------------------------------------------------
        # Trino context
        # --------------------------------------------------------------------

        "security_group":
            test.get("security_group"),

        "trino_action":
            test.get("trino_action"),

        "catalog":
            test.get("catalog"),

        "schema":
            test.get("schema"),

        "table":
            test.get("table"),

        "sql":
            test.get("sql"),

        # --------------------------------------------------------------------
        # Permission
        # --------------------------------------------------------------------

        "permission":
            test.get("permission"),

        "permission_index":
            test.get("permission_index"),

        "permission_count":
            test.get("permission_count"),

        # --------------------------------------------------------------------
        # Trino expectation
        # --------------------------------------------------------------------

        "trino_expected_allowed":
            test.get("trino_expected_allowed"),

        # --------------------------------------------------------------------
        # Exact OPA input
        # --------------------------------------------------------------------

        "input":
            opa_input,

        # --------------------------------------------------------------------
        # Exact OPA result
        # --------------------------------------------------------------------

        "opa_actual":
            opa_actual,

        # --------------------------------------------------------------------
        # Timing
        # --------------------------------------------------------------------

        "http_latency_ns":
            elapsed,

        "opa_eval_ns":
            metrics.get(
                "timer_rego_query_eval_ns"
            ),

        "opa_compile_ns":
            metrics.get(
                "timer_rego_query_compile_ns"
            ),

        "opa_parse_ns":
            metrics.get(
                "timer_rego_query_parse_ns"
            ),

        "rego_http_send_ns":
            metrics.get(
                "timer_rego_builtin_http_send_ns"
            ),

        "rego_http_requests":
            metrics.get(
                "counter_rego_builtin_http_send_network_requests"
            ),

        "opa_handler_ns":
            metrics.get(
                "timer_server_handler_ns"
            )
    }


# ============================================================================
# Skipped OPA test
# ============================================================================

def create_skipped_opa_result(
    test,
    reason,
    repetition
):
    """
    Create a result for a permission that was not sent to OPA.

    This happens when an earlier permission in the same Trino authorization
    battery returned boolean False.
    """

    return {

        # --------------------------------------------------------------------
        # Status
        # --------------------------------------------------------------------

        "status": "SKIPPED",

        "skipped": True,

        "skip_reason": reason,

        # --------------------------------------------------------------------
        # Identity
        # --------------------------------------------------------------------

        "id":
            test.get("id"),

        "trino_test_id":
            test.get("trino_test_id"),

        # --------------------------------------------------------------------
        # Trino context
        # --------------------------------------------------------------------

        "security_group":
            test.get("security_group"),

        "trino_action":
            test.get("trino_action"),

        "catalog":
            test.get("catalog"),

        "schema":
            test.get("schema"),

        "table":
            test.get("table"),

        "sql":
            test.get("sql"),

        # --------------------------------------------------------------------
        # Permission
        # --------------------------------------------------------------------

        "permission":
            test.get("permission"),

        "permission_index":
            test.get("permission_index"),

        "permission_count":
            test.get("permission_count"),

        # --------------------------------------------------------------------
        # Trino expectation
        # --------------------------------------------------------------------

        "trino_expected_allowed":
            test.get("trino_expected_allowed"),

        # --------------------------------------------------------------------
        # No OPA request
        # --------------------------------------------------------------------

        "input":
            None,

        "opa_actual":
            None,

        # --------------------------------------------------------------------
        # No timing
        # --------------------------------------------------------------------

        "http_latency_ns":
            None,

        "opa_eval_ns":
            None,

        "opa_compile_ns":
            None,

        "opa_parse_ns":
            None,

        "rego_http_send_ns":
            None,

        "rego_http_requests":
            0,

        "opa_handler_ns":
            None,

        # --------------------------------------------------------------------
        # Repetition
        # --------------------------------------------------------------------

        "repetition":
            repetition
    }


# ============================================================================
# Run tests
# ============================================================================

def run_tests(
    test_file,
    repetitions=1
):
    """
    Run OPA tests using Trino-style short-circuit authorization.

    All permissions belonging to the same trino_test_id are treated as
    one authorization battery.

    Example:

        test_000020
            1 AccessCatalog
            2 ExecuteQuery
            3 GetColumnMask
            4 GetRowFilters
            5 SelectFromColumns

    If AccessCatalog returns False:

        AccessCatalog      -> EXECUTED
        ExecuteQuery       -> SKIPPED
        GetColumnMask      -> SKIPPED
        GetRowFilters      -> SKIPPED
        SelectFromColumns  -> SKIPPED

    No OPA HTTP requests are made for skipped permissions.
    """

    test_file = Path(test_file)

    if not test_file.exists():
        raise FileNotFoundError(
            f"Test file not found:\n{test_file}"
        )

    # ------------------------------------------------------------------------
    # Load tests
    # ------------------------------------------------------------------------

    with test_file.open("r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)

    tests = data.get(
        "tests",
        []
    )

    if not tests:
        raise RuntimeError(
            f"No tests found in {test_file}"
        )

    # ------------------------------------------------------------------------
    # Group tests by Trino test ID
    # ------------------------------------------------------------------------

    batteries = {}

    for test in tests:

        trino_test_id = test.get(
            "trino_test_id"
        )

        # Fallback for tests without trino_test_id.
        if trino_test_id is None:
            trino_test_id = test.get("id")

        batteries.setdefault(
            trino_test_id,
            []
        ).append(test)

    # ------------------------------------------------------------------------
    # Sort each battery by permission index
    # ------------------------------------------------------------------------

    for battery in batteries.values():

        battery.sort(
            key=lambda test: (
                test.get("permission_index")
                if test.get("permission_index") is not None
                else 999999
            )
        )

    # ------------------------------------------------------------------------
    # Information
    # ------------------------------------------------------------------------

    print(
        f"OPA test entries: {len(tests)}"
    )

    print(
        f"Trino authorization batteries: {len(batteries)}"
    )

    print(
        f"Repetitions: {repetitions}"
    )

    total_batteries = (
        len(batteries)
        * repetitions
    )

    completed_batteries = 0

    results = []

    # ------------------------------------------------------------------------
    # Run repetitions
    # ------------------------------------------------------------------------

    for repetition in range(
        repetitions
    ):

        print()
        print(
            f"Repetition "
            f"{repetition + 1}/{repetitions}"
        )

        # --------------------------------------------------------------------
        # Run each Trino authorization battery
        # --------------------------------------------------------------------

        for trino_test_id, battery in batteries.items():

            stopped = False
            stop_reason = None

            # ---------------------------------------------------------------
            # Permissions are executed sequentially
            # ---------------------------------------------------------------

            for test in battery:

                # -----------------------------------------------------------
                # SHORT CIRCUIT
                # -----------------------------------------------------------

                if stopped:

                    result = create_skipped_opa_result(
                        test=test,
                        reason=stop_reason,
                        repetition=repetition + 1
                    )

                    results.append(result)

                    continue

                # -----------------------------------------------------------
                # Execute actual OPA request
                # -----------------------------------------------------------

                result = run_test(test)

                result["repetition"] = (
                    repetition + 1
                )

                results.append(result)

                # -----------------------------------------------------------
                # IMPORTANT:
                #
                # Only EXACT boolean False stops the battery.
                #
                # This must NOT be:
                #
                #     if not result["opa_actual"]
                #
                # because [] / {} / "" can be legitimate non-boolean OPA
                # results.
                # -----------------------------------------------------------

                if result["opa_actual"] is False:

                    stopped = True

                    stop_reason = (
                        f"Previous permission "
                        f"'{test.get('permission')}' "
                        f"returned boolean false"
                    )

                    print(
                        f"\n  {trino_test_id}: "
                        f"{test.get('permission')} = false "
                        f"-> remaining permissions skipped"
                    )

            # ---------------------------------------------------------------
            # Battery completed
            # ---------------------------------------------------------------

            completed_batteries += 1

            print(
                f"\rProgress: "
                f"{completed_batteries}/{total_batteries}",
                end="",
                flush=True
            )

    print()

    # ------------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------------

    executed = sum(
        1
        for result in results
        if result.get("skipped") is not True
    )

    skipped = sum(
        1
        for result in results
        if result.get("skipped") is True
    )

    print()
    print(
        "=" * 70
    )

    print(
        f"OPA requests actually executed: {executed}"
    )

    print(
        f"Permissions skipped: {skipped}"
    )

    print(
        f"Total result entries: {len(results)}"
    )

    print(
        "=" * 70
    )

    return results


# ============================================================================
# Percentile
# ============================================================================

def percentile(
    values,
    percentage
):

    if not values:
        return None

    values = sorted(values)

    index = int(
        len(values)
        * percentage
    )

    index = max(
        0,
        min(
            index - 1,
            len(values) - 1
        )
    )

    return values[index]


# ============================================================================
# Statistics
# ============================================================================

def print_statistics(results):

    if not results:

        print(
            "No results."
        )

        return

    # Only executed requests have timing information.
    latencies = [
        r["http_latency_ns"]
        for r in results
        if r.get("http_latency_ns") is not None
    ]

    opa_eval = [
        r["opa_eval_ns"]
        for r in results
        if r.get("opa_eval_ns") is not None
    ]

    opa_compile = [
        r["opa_compile_ns"]
        for r in results
        if r.get("opa_compile_ns") is not None
    ]

    opa_parse = [
        r["opa_parse_ns"]
        for r in results
        if r.get("opa_parse_ns") is not None
    ]

    rego_http_send = [
        r["rego_http_send_ns"]
        for r in results
        if r.get("rego_http_send_ns") is not None
    ]

    opa_handler = [
        r["opa_handler_ns"]
        for r in results
        if r.get("opa_handler_ns") is not None
    ]

    print()
    print("=" * 70)
    print(" STATELESS OPA BENCHMARK RESULTS")
    print("=" * 70)

    print(
        f"Result entries: {len(results)}"
    )

    print(
        f"OPA requests: {len(latencies)}"
    )

    print()

    # ------------------------------------------------------------------------
    # Statistics helper
    # ------------------------------------------------------------------------

    def show(
        name,
        values
    ):

        if not values:

            print(
                f"{name}: unavailable"
            )

            print()

            return

        values_ms = [
            value / 1_000_000
            for value in values
        ]

        print(name)

        print(
            f"  min:    "
            f"{min(values_ms):.3f} ms"
        )

        print(
            f"  avg:    "
            f"{statistics.mean(values_ms):.3f} ms"
        )

        print(
            f"  p50:    "
            f"{percentile(values_ms, 0.50):.3f} ms"
        )

        print(
            f"  p95:    "
            f"{percentile(values_ms, 0.95):.3f} ms"
        )

        print(
            f"  p99:    "
            f"{percentile(values_ms, 0.99):.3f} ms"
        )

        print(
            f"  max:    "
            f"{max(values_ms):.3f} ms"
        )

        print()

    show(
        "HTTP latency",
        latencies
    )

    show(
        "OPA evaluation",
        opa_eval
    )

    show(
        "OPA compilation",
        opa_compile
    )

    show(
        "OPA parsing",
        opa_parse
    )

    show(
        "Rego HTTP builtin",
        rego_http_send
    )

    show(
        "OPA server handler",
        opa_handler
    )


# ============================================================================
# Per-permission statistics
# ============================================================================

def print_permission_statistics(results):

    grouped = {}

    for result in results:

        permission = result.get(
            "permission"
        )

        latency = result.get(
            "http_latency_ns"
        )

        # Skipped permissions have no latency.
        if permission is None:
            continue

        if latency is None:
            continue

        grouped.setdefault(
            permission,
            []
        ).append(latency)

    if not grouped:
        return

    print()
    print("=" * 70)
    print(" LATENCY BY PERMISSION")
    print("=" * 70)

    for permission in sorted(grouped):

        values = [
            value / 1_000_000
            for value in grouped[permission]
        ]

        print(
            f"{permission}:"
        )

        print(
            f"  requests: "
            f"{len(values)}"
        )

        print(
            f"  avg:     "
            f"{statistics.mean(values):.3f} ms"
        )

        print(
            f"  p50:     "
            f"{percentile(values, 0.50):.3f} ms"
        )

        print(
            f"  p95:     "
            f"{percentile(values, 0.95):.3f} ms"
        )

        print(
            f"  p99:     "
            f"{percentile(values, 0.99):.3f} ms"
        )

        print()


# ============================================================================
# Battery statistics
# ============================================================================

def print_battery_statistics(results):

    grouped = {}

    for result in results:

        trino_test_id = result.get(
            "trino_test_id"
        )

        repetition = result.get(
            "repetition"
        )

        if trino_test_id is None:
            continue

        key = (
            trino_test_id,
            repetition
        )

        grouped.setdefault(
            key,
            []
        ).append(result)

    battery_latencies = []

    for _, battery in grouped.items():

        total_ns = sum(
            result["http_latency_ns"]
            for result in battery
            if result.get("http_latency_ns") is not None
        )

        battery_latencies.append(
            total_ns
        )

    if not battery_latencies:
        return

    values_ms = [
        value / 1_000_000
        for value in battery_latencies
    ]

    print()
    print("=" * 70)
    print(" COMPLETE OPA BATTERY")
    print("=" * 70)

    print(
        "Total latency of the OPA requests actually required "
        "for each Trino authorization."
    )

    print()

    print(
        f"Batteries: "
        f"{len(values_ms)}"
    )

    print(
        f"avg:       "
        f"{statistics.mean(values_ms):.3f} ms"
    )

    print(
        f"p50:       "
        f"{percentile(values_ms, 0.50):.3f} ms"
    )

    print(
        f"p95:       "
        f"{percentile(values_ms, 0.95):.3f} ms"
    )

    print(
        f"p99:       "
        f"{percentile(values_ms, 0.99):.3f} ms"
    )

    print(
        f"max:       "
        f"{max(values_ms):.3f} ms"
    )

    print()


# ============================================================================
# Save results
# ============================================================================

def save_results(
    results,
    output_directory
):

    output_directory = Path(
        output_directory
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    output_file = (
        output_directory
        / f"opa_benchmark.json"
    )

    executed = sum(
        1
        for result in results
        if result.get("skipped") is not True
    )

    skipped = sum(
        1
        for result in results
        if result.get("skipped") is True
    )

    output = {

        "opa_url":
            OPA_URL,

        "decision_path":
            DECISION_PATH,

        "number_of_result_entries":
            len(results),

        "number_of_opa_requests":
            executed,

        "number_of_skipped_permissions":
            skipped,

        "number_of_trino_tests":
            len({
                r["trino_test_id"]
                for r in results
                if r.get("trino_test_id") is not None
            }),

        "results":
            results
    }

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output,
            f,
            indent=4
        )

    print(
        f"Results saved: "
        f"{output_file}"
    )

    return output_file


# ============================================================================
# Main benchmark
# ============================================================================

def run_benchmark(
    test_file,
    results_directory,
    repetitions=1
):

    results = run_tests(
        test_file,
        repetitions
    )

    print_statistics(
        results
    )

    print_permission_statistics(
        results
    )

    print_battery_statistics(
        results
    )

    result_file = save_results(
        results,
        results_directory
    )

    return {
        "results":
            results,

        "result_file":
            result_file
    }


# ============================================================================
# Standalone
# ============================================================================

if __name__ == "__main__":

    TEST_FILE = Path(
        "generated/opa_tests.json"
    )

    RESULTS_DIRECTORY = Path(
        "results"
    )

    run_benchmark(
        test_file=TEST_FILE,
        results_directory=RESULTS_DIRECTORY,
        repetitions=5
    )