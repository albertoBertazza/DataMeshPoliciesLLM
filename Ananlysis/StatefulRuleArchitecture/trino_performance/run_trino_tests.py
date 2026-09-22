import json
import subprocess
import datetime
import time

from pathlib import Path


# ============================================================================
# Paths
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent

STATEFUL_RULE_ARCHITECTURE_DIR = BASE_DIR.parent
PROJECT_DIR = STATEFUL_RULE_ARCHITECTURE_DIR.parent

GENERATED_DIR = BASE_DIR / "generated"

TEST_FILE = GENERATED_DIR / "trino_tests.json"

RESULTS_DIR = BASE_DIR / "results"

STRUCTURE_DIR = PROJECT_DIR / "LLM" / "Structure"

USER_CREDENTIALS_FILE = STRUCTURE_DIR / "user_credentials.json"

RUN_QUERY_SCRIPT = PROJECT_DIR / "Tester" / "run_query.sh"


# ============================================================================
# OPA configuration
# ============================================================================

OPA_CONTAINER_NAME = "opa"

OPA_LOG_WAIT_SECONDS = 0.20

OPA_LOG_TIMEOUT_SECONDS = 2.0

OPA_LOG_POLL_INTERVAL_SECONDS = 0.05


# ============================================================================
# Action mapping
# ============================================================================

ACTION_TO_OPA_OPERATIONS = {

    "SelectFromTableAction": {
        "SelectFromColumns"
    },

    "ShowTablesAction": {
        "ShowTables"
    },

    "ShowSchemasAction": {
        "ShowSchemas"
    },

}


# ============================================================================
# Time helpers
# ============================================================================

def utc_timestamp():

    return (
        datetime.datetime.now(datetime.UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def timestamp_for_filename():

    return datetime.datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )


# ============================================================================
# OPA log snapshot
# ============================================================================

def get_all_opa_logs():

    try:

        proc = subprocess.run(
            [
                "docker",
                "logs",
                "--timestamps",
                OPA_CONTAINER_NAME,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    except FileNotFoundError:

        raise RuntimeError(
            "Docker executable was not found. "
            "Make sure Docker Desktop is installed and running."
        )

    logs = (
        proc.stdout
        + "\n"
        + proc.stderr
    )

    return logs.splitlines()


def get_new_opa_logs(
    before,
    after
):

    if not before:
        return after

    if len(after) >= len(before):

        if after[:len(before)] == before:

            return after[len(before):]

    last_previous_line = before[-1]

    for index in range(
        len(after) - 1,
        -1,
        -1
    ):

        if after[index] == last_previous_line:

            return after[index + 1:]

    return after


def wait_for_opa_logs(
    before
):

    deadline = (
        time.monotonic()
        + OPA_LOG_TIMEOUT_SECONDS
    )

    time.sleep(
        OPA_LOG_WAIT_SECONDS
    )

    while True:

        after = get_all_opa_logs()

        new_logs = get_new_opa_logs(
            before,
            after
        )

        if new_logs:

            return after, new_logs

        if time.monotonic() >= deadline:

            return after, new_logs

        time.sleep(
            OPA_LOG_POLL_INTERVAL_SECONDS
        )


# ============================================================================
# User credentials
# ============================================================================

def load_user_credentials():

    if not USER_CREDENTIALS_FILE.exists():

        raise FileNotFoundError(
            f"user_credentials.json not found:\n"
            f"{USER_CREDENTIALS_FILE}"
        )

    with USER_CREDENTIALS_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        users = json.load(file)

    if not isinstance(users, list):

        raise ValueError(
            "user_credentials.json must contain a JSON array"
        )

    return users


def build_security_group_users(users):

    mapping = {}

    for user in users:

        if not isinstance(user, dict):
            continue

        username = user.get("username")
        password = user.get("password")

        groups = user.get(
            "groups",
            []
        )

        if not username or not password:
            continue

        if not isinstance(groups, list):
            continue

        for group in groups:

            if not group:
                continue

            if group not in mapping:

                mapping[group] = {
                    "username": username,
                    "password": password
                }

    return mapping


def find_user_for_group(
    security_group,
    security_group_users
):

    credentials = security_group_users.get(
        security_group
    )

    if credentials is None:

        raise ValueError(
            f"No Trino user belongs to security group "
            f"'{security_group}'.\n"
            f"Check:\n{USER_CREDENTIALS_FILE}"
        )

    return credentials


# ============================================================================
# Load generated tests
# ============================================================================

def load_tests():

    if not TEST_FILE.exists():

        raise FileNotFoundError(
            f"Generated test file not found:\n"
            f"{TEST_FILE}"
        )

    with TEST_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    if not isinstance(data, dict):

        raise ValueError(
            "trino_tests.json must contain an object"
        )

    tests = data.get("tests")

    if not isinstance(tests, list):

        raise ValueError(
            "trino_tests.json does not contain a 'tests' array"
        )

    return data


# ============================================================================
# JSON helpers
# ============================================================================

def try_parse_json(value):

    if isinstance(
        value,
        (dict, list)
    ):

        return value

    if not isinstance(
        value,
        str
    ):

        return None

    try:

        return json.loads(value)

    except Exception:

        return None


# ============================================================================
# Parse Docker log line
# ============================================================================

def parse_opa_log_line(line):

    if not line:

        return None

    json_start = line.find("{")

    if json_start == -1:

        return None

    raw_json = line[json_start:]

    try:

        return json.loads(raw_json)

    except Exception:

        return None


# ============================================================================
# Count OPA calls
# ============================================================================

def count_opa_calls(
    logs,
    username
):

    count = 0

    for line in logs:

        entry = parse_opa_log_line(line)

        if entry is None:
            continue

        if entry.get("msg", "") != "Received request.":
            continue

        try:

            req_body_raw = entry.get(
                "req_body",
                "{}"
            )

            req_body = try_parse_json(
                req_body_raw
            )

            if not isinstance(
                req_body,
                dict
            ):
                continue

            input_data = req_body.get(
                "input",
                {}
            )

            if not isinstance(
                input_data,
                dict
            ):
                continue

            context = input_data.get(
                "context",
                {}
            )

            if not isinstance(
                context,
                dict
            ):
                continue

            identity = context.get(
                "identity",
                {}
            )

            if not isinstance(
                identity,
                dict
            ):
                continue

            request_user = identity.get(
                "user"
            )

            if request_user == username:

                count += 1

        except Exception:

            continue

    return count


# ============================================================================
# Parse OPA requests
# ============================================================================

def parse_opa_requests(
    logs,
    username
):

    requests = []

    for line in logs:

        entry = parse_opa_log_line(line)

        if entry is None:
            continue

        if entry.get("msg", "") != "Received request.":
            continue

        try:

            req_body_raw = entry.get(
                "req_body",
                "{}"
            )

            req_body = try_parse_json(
                req_body_raw
            )

            if not isinstance(
                req_body,
                dict
            ):
                continue

            input_data = req_body.get(
                "input",
                {}
            )

            if not isinstance(
                input_data,
                dict
            ):
                continue

            action_data = input_data.get(
                "action",
                {}
            )

            if not isinstance(
                action_data,
                dict
            ):
                action_data = {}

            action = action_data.get(
                "operation"
            )

            resource = action_data.get(
                "resource",
                {}
            )

            context = input_data.get(
                "context",
                {}
            )

            if not isinstance(
                context,
                dict
            ):
                context = {}

            identity = context.get(
                "identity",
                {}
            )

            if not isinstance(
                identity,
                dict
            ):
                identity = {}

            request_user = identity.get(
                "user"
            )

            if request_user != username:
                continue

            requests.append({

                "req_id":
                    entry.get("req_id"),

                "action":
                    action,

                "resource":
                    resource,

                "input":
                    input_data,

                "received_log":
                    entry,

            })

        except Exception:

            continue

    return requests


# ============================================================================
# Find matching OPA request
# ============================================================================

def find_matching_opa_request(
    requests,
    test
):

    # The generated tests use "permission".
    # Fall back to "action" for compatibility.
    generated_action = (
        test.get("permission")
        or test.get("action")
    )

    expected_operations = (
        ACTION_TO_OPA_OPERATIONS.get(
            generated_action,
            {generated_action}
        )
    )

    test_catalog = test.get(
        "catalog"
    )

    test_schema = test.get(
        "schema"
    )

    test_table = test.get(
        "table"
    )

    candidates = []

    for request in requests:

        operation = request.get(
            "action"
        )

        if operation not in expected_operations:

            continue

        resource = request.get(
            "resource",
            {}
        )

        candidates.append(
            request
        )

        resource_string = json.dumps(
            resource
        ).lower()

        catalog_match = (
            not test_catalog
            or str(test_catalog).lower()
            in resource_string
        )

        schema_match = (
            not test_schema
            or str(test_schema).lower()
            in resource_string
        )

        table_match = (
            not test_table
            or str(test_table).lower()
            in resource_string
        )

        if (
            catalog_match
            and schema_match
            and table_match
        ):

            return request

    if candidates:

        return candidates[-1]

    return None


# ============================================================================
# Run one test
# ============================================================================

def run_test(
    test,
    security_group_users
):

    security_group = test["security_group"]

    credentials = find_user_for_group(
        security_group,
        security_group_users
    )

    username = credentials["username"]

    password = credentials["password"]

    query = test["sql"]

    # ========================================================================
    # Validate script
    # ========================================================================

    if not RUN_QUERY_SCRIPT.exists():

        raise FileNotFoundError(
            f"run_query.sh not found:\n"
            f"{RUN_QUERY_SCRIPT}"
        )

    if not RUN_QUERY_SCRIPT.is_file():

        raise ValueError(
            f"run_query.sh is not a file:\n"
            f"{RUN_QUERY_SCRIPT}"
        )

    # ========================================================================
    # Locate Git Bash
    # ========================================================================

    git_bash_candidates = [

        Path(
            r"C:\Program Files\Git\bin\bash.exe"
        ),

        Path(
            r"C:\Program Files (x86)\Git\bin\bash.exe"
        ),

    ]

    git_bash = None

    for candidate in git_bash_candidates:

        if candidate.exists():

            git_bash = candidate

            break

    if git_bash is None:

        raise FileNotFoundError(
            "Git Bash was not found.\n\n"
            "Expected one of:\n"
            "  C:\\Program Files\\Git\\bin\\bash.exe\n"
            "  C:\\Program Files (x86)\\Git\\bin\\bash.exe\n\n"
            "Install Git for Windows or update the Git Bash path."
        )

    # ========================================================================
    # Convert Windows path to Git Bash path
    # ========================================================================

    drive = RUN_QUERY_SCRIPT.drive

    if not drive:

        raise ValueError(
            f"Could not determine drive for:\n"
            f"{RUN_QUERY_SCRIPT}"
        )

    git_bash_script_path = (
        "/"
        + drive[0].lower()
        + RUN_QUERY_SCRIPT.as_posix()[2:]
    )

    # ========================================================================
    # OPA LOG SNAPSHOT BEFORE QUERY
    # ========================================================================

    opa_logs_before = get_all_opa_logs()

    # ========================================================================
    # Start Trino iteration timer
    # ========================================================================

    started_at = utc_timestamp()

    start_monotonic = time.perf_counter_ns()

    # ========================================================================
    # Execute Trino
    # ========================================================================

    cmd = [

        str(git_bash),

        git_bash_script_path,

        "--user",
        username,

        "--password",
        password,

        "--query",
        query,

    ]

    proc = subprocess.run(

        cmd,

        capture_output=True,

        text=True,

        encoding="utf-8",

        errors="replace",

    )

    end_monotonic = time.perf_counter_ns()

    finished_at = utc_timestamp()

    execution_latency_ns = (
        end_monotonic
        - start_monotonic
    )

    # ========================================================================
    # OPA LOG SNAPSHOT AFTER QUERY
    # ========================================================================

    _, new_opa_logs = wait_for_opa_logs(
        opa_logs_before
    )

    # ========================================================================
    # OPA CALL COUNT
    # ========================================================================

    opa_call_count = count_opa_calls(
        new_opa_logs,
        username
    )

    # ========================================================================
    # OPA request
    # ========================================================================

    opa_requests = parse_opa_requests(
        new_opa_logs,
        username
    )

    opa_request = find_matching_opa_request(
        opa_requests,
        test
    )

    # ========================================================================
    # Actual result
    # ========================================================================

    actual_allowed = (
        proc.returncode == 0
    )

    # Support both names:
    #
    #   expected_allowed
    #   trino_expected_allowed
    #
    expected_value = test.get(
        "expected_allowed"
    )

    if expected_value is None:

        expected_value = test.get(
            "trino_expected_allowed"
        )

    expected_allowed = (
        bool(expected_value)
        if expected_value is not None
        else None
    )

    correct = (
        actual_allowed == expected_allowed
        if expected_allowed is not None
        else None
    )

    # ========================================================================
    # Return result
    # ========================================================================

    return {

        "status":
            "EXECUTED",

        "input": {

            "id":
                test.get("id"),

            "trino_test_id":
                test.get("trino_test_id"),

            "security_group":
                security_group,

            "username":
                username,

            "permission":
                test.get("permission"),

            "action":
                test.get("action"),

            "catalog":
                test.get("catalog"),

            "schema":
                test.get("schema"),

            "table":
                test.get("table"),

            "query":
                query,

            "expected_allowed":
                expected_allowed,

            "required_permissions":
                test.get(
                    "required_permissions",
                    []
                ),

            "permission_source":
                test.get(
                    "permission_source"
                ),

            "test_type":
                test.get(
                    "test_type"
                ),

        },

        "output": {

            "actual_allowed":
                actual_allowed,

            "correct":
                correct,

            "return_code":
                proc.returncode,

            "trino_error":
                proc.stderr.strip()
                if proc.stderr.strip()
                else None,

            "trino_output":
                proc.stdout.strip()
                if proc.stdout.strip()
                else None,

            "opa_request":
                opa_request,

            "opa_call_count":
                opa_call_count,

            "opa_log_count":
                len(new_opa_logs),

            "performance": {

                "test_execution_ns":
                    execution_latency_ns,

                "test_execution_ms":
                    execution_latency_ns / 1_000_000,

            },

        },

        "timing": {

            "started_at":
                started_at,

            "finished_at":
                finished_at,

        },

    }


# ============================================================================
# Create skipped result
# ============================================================================

def create_skipped_result(
    test,
    reason
):
    """
    Minimal result.

    IMPORTANT:
    A skipped test never calls Trino and therefore never calls OPA.
    No timing/performance/OPA information is stored.
    """

    return {

        "status":
            "SKIPPED",

        "input": {

            "id":
                test.get("id"),

            "trino_test_id":
                test.get("trino_test_id"),

            "security_group":
                test.get("security_group"),

            "permission":
                test.get("permission"),

            "catalog":
                test.get("catalog"),

            "schema":
                test.get("schema"),

            "table":
                test.get("table"),

        },

        "output": {

            "actual_allowed":
                None,

            "correct":
                None,

            "skip_reason":
                reason,

        },

    }


# ============================================================================
# Statistics helpers
# ============================================================================

def statistics(values):

    if not values:

        return {

            "count":
                0,

            "min_ns":
                None,

            "max_ns":
                None,

            "avg_ns":
                None,

            "min_ms":
                None,

            "max_ms":
                None,

            "avg_ms":
                None,

        }

    avg = (
        sum(values)
        / len(values)
    )

    return {

        "count":
            len(values),

        "min_ns":
            min(values),

        "max_ns":
            max(values),

        "avg_ns":
            avg,

        "min_ms":
            min(values) / 1_000_000,

        "max_ms":
            max(values) / 1_000_000,

        "avg_ms":
            avg / 1_000_000,

    }


# ============================================================================
# Calculate statistics
# ============================================================================

def calculate_statistics(results):

    executed_results = [

        result

        for result in results

        if result.get(
            "status"
        ) == "EXECUTED"

        and result.get("output") is not None

        and result["output"].get(
            "actual_allowed"
        ) is not None

    ]

    total_tests = len(
        results
    )

    executed_tests = len(
        executed_results
    )

    skipped_tests = sum(

        1

        for result in results

        if result.get(
            "status"
        ) == "SKIPPED"

    )

    correct = sum(

        result["output"].get(
            "correct",
            False
        )

        for result in executed_results

    )

    allowed = sum(

        1

        for result in executed_results

        if result["input"].get(
            "expected_allowed"
        ) is True

    )

    denied = (

        executed_tests
        - allowed

    )

    incorrect = (

        executed_tests
        - correct

    )

    # ========================================================================
    # Trino end-to-end performance
    #
    # ONLY executed tests are included.
    # Skipped tests have no performance measurement.
    # ========================================================================

    end_to_end = []

    for result in executed_results:

        value = (

            result["output"]

            .get(
                "performance",
                {}
            )

            .get(
                "test_execution_ns"
            )

        )

        if isinstance(
            value,
            (int, float)
        ):

            end_to_end.append(
                value
            )

    # ========================================================================
    # OPA call statistics
    # ========================================================================

    opa_call_counts = []

    for result in executed_results:

        value = result["output"].get(
            "opa_call_count"
        )

        if isinstance(
            value,
            (int, float)
        ):

            opa_call_counts.append(
                int(value)
            )

    return {

        "total_tests":
            total_tests,

        "executed_tests":
            executed_tests,

        "skipped_tests":
            skipped_tests,

        "allowed_tests":
            allowed,

        "denied_tests":
            denied,

        "correct_tests":
            correct,

        "incorrect_tests":
            incorrect,

        "accuracy":
            (
                correct / executed_tests
                if executed_tests
                else 0
            ),

        "trino_iteration_latency":
            statistics(
                end_to_end
            ),

        "opa_call_count":
            statistics(
                opa_call_counts
            ),

    }


# ============================================================================
# Print statistics
# ============================================================================

def print_statistics(stats):

    print()
    print("=" * 70)
    print(" PERFORMANCE RESULTS")
    print("=" * 70)

    print(
        f"Total tests:       "
        f"{stats['total_tests']}"
    )

    print(
        f"Executed tests:    "
        f"{stats['executed_tests']}"
    )

    print(
        f"Skipped tests:     "
        f"{stats['skipped_tests']}"
    )

    print(
        f"Allowed tests:     "
        f"{stats['allowed_tests']}"
    )

    print(
        f"Denied tests:      "
        f"{stats['denied_tests']}"
    )

    print(
        f"Correct:           "
        f"{stats['correct_tests']}"
    )

    print(
        f"Incorrect:         "
        f"{stats['incorrect_tests']}"
    )

    print(
        f"Accuracy:          "
        f"{stats['accuracy']:.2%}"
    )

    # ========================================================================
    # Trino performance
    # ========================================================================

    data = stats[
        "trino_iteration_latency"
    ]

    print()
    print(
        "TRINO ITERATION LATENCY:"
    )

    if data["count"] == 0:

        print(
            "  No measurements available"
        )

    else:

        print(
            f"  Count:   {data['count']}"
        )

        print(
            f"  Average: {data['avg_ms']:.3f} ms"
        )

        print(
            f"  Minimum: {data['min_ms']:.3f} ms"
        )

        print(
            f"  Maximum: {data['max_ms']:.3f} ms"
        )

    # ========================================================================
    # OPA calls
    # ========================================================================

    data = stats[
        "opa_call_count"
    ]

    print()
    print(
        "OPA CALL COUNT PER TRINO ITERATION:"
    )

    if data["count"] == 0:

        print(
            "  No OPA calls detected"
        )

    else:

        print(
            f"  Measurements: "
            f"{data['count']}"
        )

        print(
            f"  Average:      "
            f"{data['avg_ns']:.2f} calls"
        )

        print(
            f"  Minimum:      "
            f"{data['min_ns']} calls"
        )

        print(
            f"  Maximum:      "
            f"{data['max_ns']} calls"
        )


# ============================================================================
# Main
# ============================================================================

def run_tests():

    print("=" * 70)
    print(" TRINO PERFORMANCE TEST RUNNER")
    print("=" * 70)

    print(
        f"Tests:\n{TEST_FILE}"
    )

    print(
        f"run_query.sh:\n{RUN_QUERY_SCRIPT}"
    )

    print(
        f"Credentials:\n{USER_CREDENTIALS_FILE}"
    )

    print(
        f"Results:\n{RESULTS_DIR}"
    )

    # ========================================================================
    # Validate
    # ========================================================================

    if not RUN_QUERY_SCRIPT.exists():

        raise FileNotFoundError(
            f"run_query.sh not found:\n"
            f"{RUN_QUERY_SCRIPT}"
        )

    # ========================================================================
    # Load
    # ========================================================================

    generated = load_tests()

    tests = generated["tests"]

    metadata = generated.get(
        "metadata",
        {}
    )

    users = load_user_credentials()

    security_group_users = (
        build_security_group_users(
            users
        )
    )

    print()
    print(
        f"Tests loaded: {len(tests)}"
    )

    # ========================================================================
    # Group -> user
    # ========================================================================

    groups = sorted({

        test["security_group"]

        for test in tests

    })

    print()
    print(
        "SECURITY GROUP -> TRINO USER"
    )

    missing_groups = []

    for group in groups:

        credentials = (
            security_group_users.get(
                group
            )
        )

        if credentials is None:

            missing_groups.append(
                group
            )

            print(
                f"  {group}: MISSING"
            )

        else:

            print(
                f"  {group}: "
                f"{credentials['username']}"
            )

    if missing_groups:

        raise ValueError(
            "\nNo Trino user found for security groups:\n"
            + "\n".join(
                f"  - {group}"
                for group in missing_groups
            )
            + "\n\n"
            "Add the group to "
            "LLM/Structure/user_credentials.json."
        )

    # ========================================================================
    # Execute
    #
    # IMPORTANT:
    #
    # Every permission belonging to the same trino_test_id is a chain.
    #
    # Example:
    #
    #   test_000020_AccessCatalog
    #   test_000020_ExecuteQuery
    #   test_000020_GetColumnMask
    #   test_000020_GetRowFilters
    #   test_000020_SelectFromColumns
    #
    # If AccessCatalog returns false:
    #
    #   AccessCatalog       EXECUTE
    #   ExecuteQuery        SKIP
    #   GetColumnMask       SKIP
    #   GetRowFilters       SKIP
    #   SelectFromColumns   SKIP
    #
    # SKIPPED tests NEVER call run_test(), so they NEVER call Trino/OPA.
    # ========================================================================

    results = []

    failed_trino_tests = set()

    run_started_at = utc_timestamp()

    overall_start = time.perf_counter_ns()

    for index, test in enumerate(
        tests,
        start=1
    ):

        trino_test_id = test.get(
            "trino_test_id"
        )

        # ====================================================================
        # SKIP remaining permissions
        # ====================================================================

        if (
            trino_test_id is not None
            and trino_test_id in failed_trino_tests
        ):

            result = create_skipped_result(

                test,

                (
                    "Previous permission in "
                    f"{trino_test_id} returned false."
                )

            )

            results.append(
                result
            )

            print(
                f"[{index}/{len(tests)}] "
                f"{test.get('id')} | "
                f"SKIPPED | "
                f"trino_test_id={trino_test_id}"
            )

            continue

        # ====================================================================
        # EXECUTE CURRENT TEST
        # ====================================================================

        print(
            f"[{index}/{len(tests)}] "
            f"{test.get('id')} | "
            f"{test.get('security_group')} | "
            f"{test.get('permission')} | "
            f"{test.get('catalog')}."
            f"{test.get('schema')}."
            f"{test.get('table')}"
        )

        try:

            result = run_test(
                test,
                security_group_users
            )

            results.append(
                result
            )

            actual_allowed = (
                result["output"]
                ["actual_allowed"]
            )

            status = (

                "PASS"

                if result["output"]["correct"]

                else "FAIL"

            )

            latency_ms = (

                result["output"]
                ["performance"]
                ["test_execution_ms"]

            )

            opa_call_count = (

                result["output"]
                ["opa_call_count"]

            )

            print(
                f"    {status} | "
                f"actual={actual_allowed} | "
                f"e2e={latency_ms:.2f} ms | "
                f"opa_calls={opa_call_count}"
            )

            # ================================================================
            # THIS IS THE IMPORTANT PART
            #
            # Once the currently executed permission is denied, the complete
            # authorization chain has failed.
            #
            # Mark the trino_test_id as failed.
            #
            # The NEXT iteration will therefore NOT call run_test().
            # ================================================================

            if (
                actual_allowed is False
                and trino_test_id is not None
            ):

                failed_trino_tests.add(
                    trino_test_id
                )

                print(
                    f"    -> {trino_test_id} failed. "
                    f"Remaining permissions will be SKIPPED."
                )

        except Exception as exc:

            print(
                f"    ERROR: {exc}"
            )

            results.append({

                "status":
                    "ERROR",

                "input":
                    test,

                "output": {

                    "actual_allowed":
                        None,

                    "correct":
                        False,

                    "error":
                        str(exc),

                },

            })

    overall_end = time.perf_counter_ns()

    run_finished_at = utc_timestamp()

    # ========================================================================
    # Statistics
    # ========================================================================

    stats = calculate_statistics(
        results
    )

    total_run_time_ns = (
        overall_end
        - overall_start
    )

    stats["total_run_time_ns"] = (
        total_run_time_ns
    )

    stats["total_run_time_ms"] = (
        total_run_time_ns
        / 1_000_000
    )

    # ========================================================================
    # Save
    # ========================================================================

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    output_file = (
        RESULTS_DIR
        / f"trino_test_results.json"
    )

    report = {

        "metadata": {

            "run_started_at":
                run_started_at,

            "run_finished_at":
                run_finished_at,

            "source_test_file":
                str(TEST_FILE),

            "user_credentials_file":
                str(USER_CREDENTIALS_FILE),

            "number_of_tests":
                len(tests),

            "generated_metadata":
                metadata,

        },

        "statistics":
            stats,

        "results":
            results,

    }

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    print_statistics(
        stats
    )

    print()
    print(
        f"Saved:\n{output_file}"
    )

    return report


# ============================================================================
# Standalone
# ============================================================================

if __name__ == "__main__":

    run_tests()