import json
import statistics
import time
from datetime import datetime
from pathlib import Path

import requests


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

OPA_URL = "http://localhost:8182"

# TODO:
# This should eventually be discovered automatically from the Rego package.
DECISION_PATH = "/v1/data/trino/authz/allow"


# ---------------------------------------------------------------------------
# Single test
# ---------------------------------------------------------------------------

def run_test(
    test
):

    url = (
        OPA_URL
        + DECISION_PATH
    )

    start = time.perf_counter_ns()

    response = requests.post(
        url,
        params={
            "metrics": "true"
        },
        json={
            "input": test["input"]
        },
        timeout=30
    )

    elapsed = (
        time.perf_counter_ns()
        - start
    )

    response.raise_for_status()

    data = response.json()

    metrics = data.get(
        "metrics",
        {}
    )

    # Do not silently turn a missing decision into None.
    if "result" not in data:

        raise RuntimeError(
            "OPA did not return a decision.\n"
            f"URL: {url}\n"
            f"Test: {test.get('id')}\n"
            f"Response:\n"
            f"{json.dumps(data, indent=4)}"
        )

    opa_actual = data.get(
        "result"
    )

    llm_expected = test.get(
        "expected"
    )

    return {
        "id": test["id"],

        "description":
            test.get(
                "description"
            ),

        "category":
            test.get(
                "category"
            ),

        "input":
            test["input"],

        "llm_expected":
            llm_expected,

        "opa_actual":
            opa_actual,

        "llm_correct":
            opa_actual == llm_expected,

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


# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------

def run_tests(
    test_file,
    repetitions=1
):

    test_file = Path(
        test_file
    )

    with test_file.open(
        "r",
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

    results = []

    print(
        f"Tests: {len(tests)}"
    )

    print(
        f"Repetitions: {repetitions}"
    )

    total = (
        len(tests)
        * repetitions
    )

    completed = 0

    for repetition in range(
        repetitions
    ):

        print(
            f"\nRepetition "
            f"{repetition + 1}/{repetitions}"
        )

        for test in tests:

            result = run_test(
                test
            )

            result["repetition"] = (
                repetition + 1
            )

            results.append(
                result
            )

            completed += 1

            print(
                f"\rProgress: "
                f"{completed}/{total}",
                end="",
                flush=True
            )

    print()

    return results


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def percentile(
    values,
    percentage
):

    if not values:
        return None

    values = sorted(
        values
    )

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


def print_statistics(
    results
):

    if not results:

        print(
            "No results."
        )

        return

    latencies = [
        r["http_latency_ns"]
        for r in results
        if r["http_latency_ns"]
        is not None
    ]

    opa_eval = [
        r["opa_eval_ns"]
        for r in results
        if r["opa_eval_ns"]
        is not None
    ]

    opa_compile = [
        r["opa_compile_ns"]
        for r in results
        if r["opa_compile_ns"]
        is not None
    ]

    opa_parse = [
        r["opa_parse_ns"]
        for r in results
        if r["opa_parse_ns"]
        is not None
    ]

    rego_http_send = [
        r["rego_http_send_ns"]
        for r in results
        if r["rego_http_send_ns"]
        is not None
    ]

    opa_handler = [
        r["opa_handler_ns"]
        for r in results
        if r["opa_handler_ns"]
        is not None
    ]

    llm_correct = sum(
        r["llm_correct"]
        for r in results
    )

    print()
    print("=" * 60)
    print(" RESULTS")
    print("=" * 60)

    print(
        f"Requests: "
        f"{len(results)}"
    )

    print(
        f"LLM expected correctly: "
        f"{llm_correct}/{len(results)} "
        f"("
        f"{100 * llm_correct / len(results):.2f}%"
        f")"
    )

    print()

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


# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------

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

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    output_file = (
        output_directory
        / f"opa_benchmark_{timestamp}.json"
    )

    output = {
        "timestamp":
            timestamp,

        "opa_url":
            OPA_URL,

        "decision_path":
            DECISION_PATH,

        "number_of_requests":
            len(results),

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

    print()
    print(
        f"Results saved: "
        f"{output_file}"
    )

    return output_file


# ---------------------------------------------------------------------------
# Main benchmark function
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    TEST_FILE = Path(
        "generated/opa_tests_100.json"
    )

    RESULTS_DIRECTORY = Path(
        "results"
    )

    run_benchmark(
        test_file=TEST_FILE,
        results_directory=RESULTS_DIRECTORY,
        repetitions=100
    )