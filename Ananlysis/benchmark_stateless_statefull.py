import subprocess
import time
from collections import defaultdict
import statistics
import matplotlib.pyplot as plt
import requests
import shutil
from pathlib import Path
from Function.jsonHelper import load_json
from Pipelines.costantPath import DOCKER_COMPOSE_TRINO_DIR, DOCKER_COMPOSE_OPA_DIR, SOURCE_FILE, TARGET_DIRECTORIES
from StatefulRuleArchitecture.trino_performance.benchmark_trino import benchmark_stateful_architecture
from StatelessRuleArchitecture.opa_performance.benchmark_opa import benchmark_stateless_architecture





# ============================================================================
# Remove existing Rego files
# ============================================================================

def remove_rego_files(directory: Path):

    if not directory.exists():
        directory.mkdir(
            parents=True,
            exist_ok=True
        )

    removed = []

    for file in directory.glob("*.rego"):

        file.unlink()

        removed.append(file)

    return removed


# ============================================================================
# Copy policy
# ============================================================================

def copy_policy():

    print("=" * 70)
    print(" COPYING POLICY")
    print("=" * 70)

    print()
    print(f"Source:")
    print(f"  {SOURCE_FILE}")

    if not SOURCE_FILE.exists():

        raise FileNotFoundError(
            f"Source policyReference.rego not found:\n"
            f"{SOURCE_FILE}"
        )

    if SOURCE_FILE.name != "policyReference.rego":

        raise RuntimeError(
            "SOURCE_FILE must be policyReference.rego"
        )

    for target_directory in TARGET_DIRECTORIES:

        print()
        print("-" * 70)
        print(f"Target:")
        print(f"  {target_directory}")

        # ------------------------------------------------------------
        # Remove existing .rego files
        # ------------------------------------------------------------

        removed = remove_rego_files(
            target_directory
        )

        if removed:

            print()
            print("Removed:")

            for file in removed:
                print(f"  {file.name}")

        else:

            print()
            print("No existing .rego files.")

        # ------------------------------------------------------------
        # Copy policy
        # ------------------------------------------------------------

        target_file = (
            target_directory
            / "policyReference.rego"
        )

        shutil.copy2(
            SOURCE_FILE,
            target_file
        )

        print()
        print("Copied:")
        print(f"  {target_file}")

    print()
    print("=" * 70)
    print(" DONE")
    print("=" * 70)



# =====================================================================
# Start Docker Compose
# =====================================================================
def start_docker_trino():
    print("Starting Docker Compose in:")
    print(DOCKER_COMPOSE_TRINO_DIR)
    
    subprocess.run(
        [
            "docker",
            "compose",
            "up",
            "-d",
        ],
        cwd=str(DOCKER_COMPOSE_TRINO_DIR),
        check=True
    )
    
    
    # =====================================================================
    # Wait for Trino container to become healthy
    # =====================================================================
    
    print()
    print("Waiting for Trino to become healthy...")
    
    for attempt in range(60):
    
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                "trino-coordinator",
            ],
            capture_output=True,
            text=True,
        )
    
        status = result.stdout.strip()
    
        print(
            f"  Trino health: {status or 'unknown'}"
        )
    
        if status == "healthy":
    
            print("Trino is ready.")
            break
    
        time.sleep(2)
    
    else:

        raise RuntimeError(
            "Trino did not become healthy within 120 seconds."
        )

def start_docker_opa():

    print("Starting Docker Compose in:")
    print(DOCKER_COMPOSE_OPA_DIR)

    subprocess.run(
        [
            "docker",
            "compose",
            "up",
            "-d"
        ],
        cwd=str(DOCKER_COMPOSE_OPA_DIR),
        check=True
    )

    print()
    print("Waiting for OPA to become ready...")

    health_url = "http://localhost:8182/health"

    for attempt in range(60):

        try:

            response = requests.get(
                health_url,
                timeout=2
            )

            status = response.status_code

        except requests.RequestException:

            status = None

        print(
            f"  OPA health: "
            f"{status if status else 'not ready'}"
        )

        if status == 200:

            print("OPA is ready.")
            return

        time.sleep(2)

    raise RuntimeError(
        "OPA did not become healthy within 120 seconds."
    )


# =====================================================================
# Stop Docker Compose
# =====================================================================
def stop_docker_trino():
    print("Stopping Docker Compose in:")
    print(DOCKER_COMPOSE_TRINO_DIR)

    subprocess.run(
        [
            "docker",
            "compose",
            "down"
        ],
        cwd=str(DOCKER_COMPOSE_TRINO_DIR),
        check=True
    )

    time.sleep(4)

def stop_docker_opa():
    print("Stopping Docker Compose in:")
    print(DOCKER_COMPOSE_OPA_DIR)

    subprocess.run(
        [
            "docker",
            "compose",
            "down"
        ],
        cwd=str(DOCKER_COMPOSE_OPA_DIR),
        check=True
    )

    time.sleep(4)

# =====================================================================
# Benchmark
# =====================================================================


# Set to None to generate every possible test.
MAX_TESTS = 20

# number of repetition to get an average
MAX_REPETITION=1


def collect_stateful():
    # run trino
    start_docker_trino()
    time.sleep(10)

    print("=" * 70)
    print(" STATEFUL ARCHITECTURE MEASUREMENT")
    print("=" * 70)

    # benchmark STATEFUL architecture
    benchmark_stateful_architecture(MAX_TESTS)

    stop_docker_trino()


def collect_stateless():

    start_docker_opa()

    print("=" * 70)
    print(" STATELESS ARCHITECTURE MEASUREMENT")
    print("=" * 70)

    benchmark_stateless_architecture(MAX_REPETITION)

    stop_docker_opa()

def collect_data():
    # stop all
    stop_docker_trino()
    stop_docker_opa()

    collect_stateful()
    collect_stateless()




# ============================================================================
# Build comparison data
# ============================================================================

def build_benchmark_comparison(stateful_file, stateless_file):
    """
    Compare Stateful Trino authorization against Stateless OPA authorization.

    Stateful JSON:
        output.performance.test_execution_ns
        output.opa_call_count

    Stateless JSON:
        results[*].http_latency_ns
        results[*].status == "EXECUTED"

    Returns:
        dict[test_id] = {
            ...
        }
    """

    stateful = load_json(stateful_file)
    stateless = load_json(stateless_file)

    # ------------------------------------------------------------------------
    # Stateful results
    # ------------------------------------------------------------------------

    stateful_by_test = {}

    for result in stateful.get("results", []):

        test_id = result.get("input", {}).get("id")

        if test_id is None:
            continue

        output = result.get("output", {})
        performance = output.get("performance", {})

        latency_ns = performance.get(
            "test_execution_ns"
        )

        opa_calls = output.get(
            "opa_call_count"
        )

        stateful_by_test[test_id] = {
            "test_id": test_id,

            "security_group":
                result.get("input", {}).get("security_group"),

            "username":
                result.get("input", {}).get("username"),

            "action":
                result.get("input", {}).get("action"),

            "sql":
                result.get("input", {}).get("query"),

            "expected_allowed":
                result.get("input", {}).get("expected_allowed"),

            "actual_allowed":
                output.get("actual_allowed"),

            "correct":
                output.get("correct"),

            "latency_ns":
                latency_ns,

            "opa_calls":
                opa_calls or 0
        }

    # ------------------------------------------------------------------------
    # Stateless results
    #
    # IMPORTANT:
    #
    # Only EXECUTED entries represent actual HTTP requests.
    # SKIPPED permissions must NOT contribute latency.
    # ------------------------------------------------------------------------

    stateless_by_test = defaultdict(
        lambda: {
            "latency_ns": 0,
            "opa_calls": 0,
            "executed_permissions": [],
            "skipped_permissions": []
        }
    )

    for result in stateless.get("results", []):

        test_id = result.get(
            "trino_test_id"
        )

        if test_id is None:
            continue

        status = result.get(
            "status"
        )

        permission = result.get(
            "permission"
        )

        if status == "EXECUTED":

            latency_ns = result.get(
                "http_latency_ns"
            )

            if latency_ns is not None:

                stateless_by_test[test_id][
                    "latency_ns"
                ] += latency_ns

            stateless_by_test[test_id][
                "opa_calls"
            ] += 1

            stateless_by_test[test_id][
                "executed_permissions"
            ].append(permission)

        elif status == "SKIPPED":

            stateless_by_test[test_id][
                "skipped_permissions"
            ].append(permission)

    # ------------------------------------------------------------------------
    # Combine
    # ------------------------------------------------------------------------

    comparison = {}

    for test_id, stateful_data in stateful_by_test.items():

        stateless_data = stateless_by_test.get(
            test_id,
            {
                "latency_ns": 0,
                "opa_calls": 0,
                "executed_permissions": [],
                "skipped_permissions": []
            }
        )

        stateful_latency = (
            stateful_data["latency_ns"]
        )

        stateless_latency = (
            stateless_data["latency_ns"]
        )

        speedup = None
        reduction_percent = None

        if (
            stateful_latency is not None
            and stateful_latency > 0
            and stateless_latency > 0
        ):

            speedup = (
                stateless_latency
                / stateful_latency
            )

            reduction_percent = (
                (
                    stateless_latency
                    - stateful_latency
                )
                / stateless_latency
            ) * 100

        comparison[test_id] = {

            **stateful_data,

            "stateful_latency_ns":
                stateful_latency,

            "stateful_opa_calls":
                stateful_data["opa_calls"],

            "stateless_latency_ns":
                stateless_latency,

            "stateless_opa_calls":
                stateless_data["opa_calls"],

            "executed_permissions":
                stateless_data[
                    "executed_permissions"
                ],

            "skipped_permissions":
                stateless_data[
                    "skipped_permissions"
                ],

            "speedup":
                speedup,

            "latency_reduction_percent":
                reduction_percent
        }

    return comparison


# ============================================================================
# Utility
# ============================================================================

def ns_to_ms(value):
    if value is None:
        return None

    return value / 1_000_000


def percentile(values, p):

    if not values:
        return None

    values = sorted(values)

    index = int(len(values) * p)

    index = max(
        0,
        min(
            index - 1,
            len(values) - 1
        )
    )

    return values[index]


# ============================================================================
# Plot benchmark
# ============================================================================

def plot_benchmark_comparison(
    stateful_file,
    stateless_file,
    output_directory="benchmark_plots"
):
    """
    Generate graphs comparing Stateful Trino authorization
    against Stateless OPA authorization.

    Generated graphs:

        1. latency_comparison.png
        2. speedup.png
        3. opa_calls_comparison.png
        4. latency_reduction.png

    Also prints aggregate statistics.
    """

    output_directory = Path(
        output_directory
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    comparison = build_benchmark_comparison(
        stateful_file,
        stateless_file
    )

    if not comparison:

        raise RuntimeError(
            "No matching Trino tests found "
            "between the two benchmark files."
        )

    # ------------------------------------------------------------------------
    # Sort test IDs numerically
    # ------------------------------------------------------------------------

    test_ids = sorted(
        comparison.keys(),
        key=lambda x: int(
            x.split("_")[-1]
        )
    )

    stateful_latency = [
        ns_to_ms(
            comparison[test_id][
                "stateful_latency_ns"
            ]
        )
        for test_id in test_ids
    ]

    stateless_latency = [
        ns_to_ms(
            comparison[test_id][
                "stateless_latency_ns"
            ]
        )
        for test_id in test_ids
    ]

    stateful_calls = [
        comparison[test_id][
            "stateful_opa_calls"
        ]
        for test_id in test_ids
    ]

    stateless_calls = [
        comparison[test_id][
            "stateless_opa_calls"
        ]
        for test_id in test_ids
    ]

    speedups = [
        comparison[test_id][
            "speedup"
        ]
        for test_id in test_ids
    ]

    reductions = [
        comparison[test_id][
            "latency_reduction_percent"
        ]
        for test_id in test_ids
    ]

    # =========================================================================
    # 1. LATENCY COMPARISON
    # =========================================================================

    x = range(len(test_ids))

    width = 0.38

    plt.figure(
        figsize=(16, 8)
    )

    plt.bar(
        [i - width / 2 for i in x],
        stateful_latency,
        width=width,
        label="Stateful Trino"
    )

    plt.bar(
        [i + width / 2 for i in x],
        stateless_latency,
        width=width,
        label="Stateless OPA"
    )

    plt.xlabel(
        "Trino authorization test"
    )

    plt.ylabel(
        "Total latency (ms)"
    )

    plt.title(
        "Stateful Trino vs Stateless OPA Authorization Latency"
    )

    plt.xticks(
        list(x),
        test_ids,
        rotation=45,
        ha="right"
    )

    plt.legend()

    plt.grid(
        axis="y",
        alpha=0.3
    )

    plt.tight_layout()

    latency_file = (
        output_directory
        / "latency_comparison.png"
    )

    plt.savefig(
        latency_file,
        dpi=200
    )

    plt.close()

    # =========================================================================
    # 2. SPEEDUP
    # =========================================================================

    plt.figure(
        figsize=(16, 8)
    )

    plt.bar(
        list(x),
        speedups
    )

    plt.axhline(
        1.0,
        linestyle="--",
        linewidth=1
    )

    plt.xlabel(
        "Trino authorization test"
    )

    plt.ylabel(
        "Speedup (Stateless / Stateful)"
    )

    plt.title(
        "Stateful Trino Speedup over Stateless OPA"
    )

    plt.xticks(
        list(x),
        test_ids,
        rotation=45,
        ha="right"
    )

    plt.grid(
        axis="y",
        alpha=0.3
    )

    plt.tight_layout()

    speedup_file = (
        output_directory
        / "speedup.png"
    )

    plt.savefig(
        speedup_file,
        dpi=200
    )

    plt.close()

    # =========================================================================
    # 3. OPA CALL COUNT
    # =========================================================================

    plt.figure(
        figsize=(16, 8)
    )

    plt.bar(
        [i - width / 2 for i in x],
        stateful_calls,
        width=width,
        label="Stateful Trino"
    )

    plt.bar(
        [i + width / 2 for i in x],
        stateless_calls,
        width=width,
        label="Stateless OPA"
    )

    plt.xlabel(
        "Trino authorization test"
    )

    plt.ylabel(
        "Number of OPA requests"
    )

    plt.title(
        "OPA Requests per Trino Authorization"
    )

    plt.xticks(
        list(x),
        test_ids,
        rotation=45,
        ha="right"
    )

    plt.legend()

    plt.grid(
        axis="y",
        alpha=0.3
    )

    plt.tight_layout()

    calls_file = (
        output_directory
        / "opa_calls_comparison.png"
    )

    plt.savefig(
        calls_file,
        dpi=200
    )

    plt.close()

    # =========================================================================
    # 4. LATENCY REDUCTION
    # =========================================================================

    plt.figure(
        figsize=(16, 8)
    )

    plt.bar(
        list(x),
        reductions
    )

    plt.axhline(
        0,
        linestyle="--",
        linewidth=1
    )

    plt.xlabel(
        "Trino authorization test"
    )

    plt.ylabel(
        "Latency reduction (%)"
    )

    plt.title(
        "Latency Reduction of Stateful Trino vs Stateless OPA"
    )

    plt.xticks(
        list(x),
        test_ids,
        rotation=45,
        ha="right"
    )

    plt.grid(
        axis="y",
        alpha=0.3
    )

    plt.tight_layout()

    reduction_file = (
        output_directory
        / "latency_reduction.png"
    )

    plt.savefig(
        reduction_file,
        dpi=200
    )

    plt.close()

    # =========================================================================
    # Aggregate statistics
    # =========================================================================

    stateful_values = [
        v for v in stateful_latency
        if v is not None
    ]

    stateless_values = [
        v for v in stateless_latency
        if v is not None
    ]

    valid_speedups = [
        v for v in speedups
        if v is not None
    ]

    valid_reductions = [
        v for v in reductions
        if v is not None
    ]

    print()
    print("=" * 80)
    print(" STATEFUL TRINO vs STATELESS OPA")
    print("=" * 80)

    print(
        f"Tests compared: "
        f"{len(test_ids)}"
    )

    print()

    print("LATENCY")
    print("-" * 80)

    print(
        f"Stateful total:   "
        f"{sum(stateful_values):.3f} ms"
    )

    print(
        f"Stateless total:  "
        f"{sum(stateless_values):.3f} ms"
    )

    print(
        f"Stateful average: "
        f"{statistics.mean(stateful_values):.3f} ms"
    )

    print(
        f"Stateless average:"
        f"{statistics.mean(stateless_values):.3f} ms"
    )

    print()

    print("STATEFUL")

    print(
        f"  p50: "
        f"{percentile(stateful_values, 0.50):.3f} ms"
    )

    print(
        f"  p95: "
        f"{percentile(stateful_values, 0.95):.3f} ms"
    )

    print(
        f"  p99: "
        f"{percentile(stateful_values, 0.99):.3f} ms"
    )

    print()

    print("STATELESS")

    print(
        f"  p50: "
        f"{percentile(stateless_values, 0.50):.3f} ms"
    )

    print(
        f"  p95: "
        f"{percentile(stateless_values, 0.95):.3f} ms"
    )

    print(
        f"  p99: "
        f"{percentile(stateless_values, 0.99):.3f} ms"
    )

    print()

    print("SPEEDUP")
    print("-" * 80)

    print(
        f"Average speedup: "
        f"{statistics.mean(valid_speedups):.3f}x"
    )

    print(
        f"Median speedup:  "
        f"{statistics.median(valid_speedups):.3f}x"
    )

    print(
        f"Minimum speedup: "
        f"{min(valid_speedups):.3f}x"
    )

    print(
        f"Maximum speedup: "
        f"{max(valid_speedups):.3f}x"
    )

    print()

    print("LATENCY REDUCTION")
    print("-" * 80)

    print(
        f"Average reduction: "
        f"{statistics.mean(valid_reductions):.2f}%"
    )

    print(
        f"Median reduction:  "
        f"{statistics.median(valid_reductions):.2f}%"
    )

    print()

    print("OPA CALLS")
    print("-" * 80)

    print(
        f"Stateful total calls:  "
        f"{sum(stateful_calls)}"
    )

    print(
        f"Stateless total calls: "
        f"{sum(stateless_calls)}"
    )

    print(
        f"Stateful average:      "
        f"{statistics.mean(stateful_calls):.2f}"
    )

    print(
        f"Stateless average:     "
        f"{statistics.mean(stateless_calls):.2f}"
    )

    print()

    print("OUTPUT")
    print("-" * 80)

    print(
        f"Latency graph: "
        f"{latency_file}"
    )

    print(
        f"Speedup graph: "
        f"{speedup_file}"
    )

    print(
        f"OPA calls graph: "
        f"{calls_file}"
    )

    print(
        f"Reduction graph: "
        f"{reduction_file}"
    )

    print("=" * 80)

    return comparison


def draw_plot():
    stateful_file = (
        "StatefulRuleArchitecture/"
        "trino_performance/"
        "results/"
        "trino_test_results.json"
    )

    stateless_file = (
        "StatelessRuleArchitecture/"
        "opa_performance/"
        "results/"
        "opa_benchmark.json"
    )

    comparison = plot_benchmark_comparison(
        stateful_file=stateful_file,
        stateless_file=stateless_file,
        output_directory="benchmark_comparison"
    )


def benchmark():
    copy_policy()
    collect_data()
    print()
    print("Starting benchmark...")
    draw_plot();



if __name__ == "__main__":
    benchmark()
