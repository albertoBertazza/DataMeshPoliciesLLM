from pathlib import Path
import os

from TreePermission.tree_builder import build_permission_tree_from_directory
from StatefulRuleArchitecture.trino_performance.generate_tests import generate_tests
from StatefulRuleArchitecture.trino_performance.run_trino_tests import run_tests

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

DATA_MESH_DIR = Path(
    __file__
).resolve().parent.parent.parent

print(DATA_MESH_DIR)

LLM_DIR = os.path.join(
    DATA_MESH_DIR,
    "LLM"
)

STRUCTURE_DIR = os.path.join(
    LLM_DIR,
    "Structure"
)

CHECK_FOR_ACTION_PATH = os.path.join(
    STRUCTURE_DIR,
    "checkForAction.json"
)

SECURITY_GROUPS_PATH = os.path.join(
    STRUCTURE_DIR,
    "security_groups.json"
)

DATA_MESH_STRUCTURE_PATH = os.path.join(
    STRUCTURE_DIR,
    "data_mesh.json"
)


DOCKER_COMPOSE_PATH = os.path.join(
    DATA_MESH_DIR,
    "docker-compose"
)

OPA_FILE_PATH = os.path.join(
    DOCKER_COMPOSE_PATH,
    "opa"
)

OUTPUT_PATH = os.path.join(os.path.join(os.path.join(os.path.join(DATA_MESH_DIR,"StatefulRuleArchitecture" ), "trino_performance"), "tree_permission"), "tree.json")



# Set to None to generate every possible test.
MAX_TESTS = 20



def benchmark_stateful_architecture(max_test):

    print()
    print("=" * 70)
    print(" TRINO POLICY BENCHMARK")
    print("=" * 70)

    build_permission_tree_from_directory(OPA_FILE_PATH, CHECK_FOR_ACTION_PATH, SECURITY_GROUPS_PATH, OUTPUT_PATH)

    generate_tests(
        max_tests=max_test
    )

    run_tests()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    benchmark_stateful_architecture(MAX_TESTS)