from pathlib import Path

from StatelessRuleArchitecture.opa_performance.generate_opa_tests_from_trino_test import generate_opa_tests
from StatelessRuleArchitecture.opa_performance.run_opa_tests import run_benchmark


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(
    __file__
).resolve().parent


GENERATED_DIR = (
    BASE_DIR
    / "generated"
)


RESULTS_DIR = (
    BASE_DIR
    / "results"
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NUMBER_OF_TESTS = 5

REPETITIONS = 2


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def benchmark_stateless_architecture(repetition):

    print()
    print("=" * 70)
    print(" OPA POLICY BENCHMARK")
    print("=" * 70)

    # -------------------------------------------------------
    # Step 1: Generate tests using LLM
    # -------------------------------------------------------

    print()
    print("[1/2] Generating OPA tests...")

    generated = generate_opa_tests()

    test_file = (
        GENERATED_DIR
        / f"opa_tests.json"
    )

    if not test_file.exists():

        raise RuntimeError(
            f"Generated test file does not exist: "
            f"{test_file}"
        )

    # -------------------------------------------------------
    # Step 2: Execute against OPA
    # -------------------------------------------------------

    print()
    print("[2/2] Running OPA benchmark...")

    result = run_benchmark(
        test_file=test_file,
        results_directory=RESULTS_DIR,
        repetitions=repetition,
    )

    print()
    print("=" * 70)
    print(" BENCHMARK COMPLETE")
    print("=" * 70)

    print()
    print(
        f"Test file:   {test_file}"
    )

    print(
        f"Result file: "
        f"{result['result_file']}"
    )

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    benchmark_stateless_architecture(REPETITIONS)