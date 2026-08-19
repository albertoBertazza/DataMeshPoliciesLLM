import json
from pathlib import Path


# ============================================================================
# Configuration
# ============================================================================

BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    BASE_DIR
    / "StatefulRuleArchitecture"
    / "trino_performance"
    / "generated"
    / "trino_tests.json"
)

OUTPUT_DIR = (
    BASE_DIR
    / "StatelessRuleArchitecture"
    / "opa_performance"
    / "generated"
)

OUTPUT_FILE = OUTPUT_DIR / "opa_tests.json"


# ============================================================================
# Load Trino tests
# ============================================================================

def load_trino_tests():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Trino test file not found:\n{INPUT_FILE}"
        )

    with INPUT_FILE.open(
        "r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)

    tests = data.get("tests")

    if not isinstance(tests, list):
        raise RuntimeError(
            "trino_tests.json does not contain a valid 'tests' array"
        )

    return data, tests


# ============================================================================
# Build OPA input
# ============================================================================

def build_opa_input(
    trino_test,
    permission
):

    return {
        "username": trino_test["security_group"],
        "catalog": trino_test["catalog"],
        "schema": trino_test["schema"],
        "table": trino_test["table"],
        "action": permission
    }


# ============================================================================
# Generate OPA battery
# ============================================================================

def generate_opa_tests():

    print("=" * 70)
    print(" STATELESS OPA INTERACTION TEST GENERATOR")
    print("=" * 70)

    print()
    print(f"Input:")
    print(INPUT_FILE)

    metadata, trino_tests = load_trino_tests()

    print(
        f"Loaded {len(trino_tests)} Trino tests"
    )

    opa_tests = []

    for trino_test in trino_tests:

        trino_id = trino_test["id"]

        required_permissions = trino_test.get(
            "required_permissions",
            []
        )

        if not required_permissions:
            print(
                f"WARNING: {trino_id} has no required permissions"
            )
            continue

        for index, permission in enumerate(
            required_permissions,
            start=1
        ):

            opa_test = {
                "id": f"{trino_id}_{permission}",
                "trino_test_id": trino_id,

                "security_group":
                    trino_test["security_group"],

                "action":
                    trino_test["action"],

                "permission":
                    permission,

                "catalog":
                    trino_test["catalog"],

                "schema":
                    trino_test["schema"],

                "table":
                    trino_test["table"],

                "sql":
                    trino_test["sql"],

                "expected_allowed":
                    trino_test["expected_allowed"],

                "test_type":
                    trino_test["test_type"],

                "permission_index":
                    index,

                "permission_count":
                    len(required_permissions),

                "input":
                    build_opa_input(
                        trino_test,
                        permission
                    )
            }

            opa_tests.append(
                opa_test
            )

    # ------------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------------

    allowed = sum(
        1
        for test in opa_tests
        if test["expected_allowed"]
    )

    denied = len(opa_tests) - allowed

    output = {
        "metadata": {
            "source": str(INPUT_FILE),
            "number_of_trino_tests": len(trino_tests),
            "number_of_opa_tests": len(opa_tests),
            "allowed_opa_tests": allowed,
            "denied_opa_tests": denied,
            "generation_type": "deterministic_permission_expansion"
        },
        "tests": opa_tests
    }

    # ------------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
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
        f"Generated {len(opa_tests)} OPA tests"
    )

    print(
        f"Allowed: {allowed}"
    )

    print(
        f"Denied:  {denied}"
    )

    print()
    print(
        f"Saved: {OUTPUT_FILE}"
    )

    return output


# ============================================================================
# Standalone
# ============================================================================

if __name__ == "__main__":

    generate_opa_tests()