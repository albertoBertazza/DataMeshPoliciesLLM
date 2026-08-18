from pathlib import Path

from generate_opa_tests import generate_opa_tests
from run_opa_tests import run_benchmark


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

def benchmark():

    print()
    print("=" * 70)
    print(" OPA POLICY BENCHMARK")
    print("=" * 70)

    # -------------------------------------------------------
    # Step 1: Generate tests using LLM
    # -------------------------------------------------------

    print()
    print("[1/2] Generating OPA tests...")

    generated = generate_opa_tests(
        number_of_tests=NUMBER_OF_TESTS
    )

    test_file = (
        GENERATED_DIR
        / f"opa_tests_{NUMBER_OF_TESTS}.json"
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
        repetitions=REPETITIONS
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

    benchmark()