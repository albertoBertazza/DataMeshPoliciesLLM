import json
import shutil
import time
from pathlib import Path
from typing import Optional

import requests
import subprocess

from Helper.action_resolver import AuthorizationResolver
from Helper.generate_opa_test import generate_opa_tests
from Helper.run_opa_test import run_opa_tests
from Pipelines.costantPath import DATA_STATELESS_PATH, DATA_STATEFUL_PATH, DATA_JSON_EXAMPLE_ANALYSIS, \
    STATEFUL_OPA_DOCKER_DIR, CHECK_FOR_ACTION_PATH, DATA_MESH_STRUCTURE_PATH, USER_CREDENTIALS_PATH, \
        PERMISSION_DEPTH_PATH, OPA_URL_STATEFUL, OUTPUT_STATEFUL_PATH, STATELESS_OPA_DOCKER_DIR, OPA_URL_STATELESS, OUTPUT_STATELESS_PATH, STATELESS_PORT, STATEFUL_PORT

def start_docker_opa(opa_dir, health_port):
    opa_dir = Path(opa_dir)
    print(f"Starting {opa_dir.name}")
    subprocess.run( ["docker", "compose", "up", "-d"], cwd=str(opa_dir), check=True)
    health_url = f"http://localhost:{health_port}/health"
    print(f"Waiting for OPA on {health_url}...")
    for attempt in range(60):
        try:
            response = requests.get( health_url, timeout=2)
            print(f"  OPA health: {response.status_code}")
            if response.status_code == 200:
                print("OPA is ready.")
                return
        except requests.RequestException as exc:
            print(f"  OPA health: not ready ({exc})")
        time.sleep(2)
    print("\nOPA did not become ready. Docker logs:")
    subprocess.run( ["docker", "compose", "logs", "--tail", "100"], cwd=str(opa_dir))
    raise RuntimeError(f"OPA did not become ready on port {health_port}.")

def stop_docker_opa(opa_dir):
    print("Stopping Docker Compose in:")
    print(opa_dir)
    subprocess.run( [ "docker", "compose", "down" ], cwd=str(opa_dir), check=True )
    time.sleep(4)

def generate_and_run_opa_tests(
    action_permissions_file: str | Path,
    data_mesh_file: str | Path,
    users_file: str | Path,
    permission_depth_file: str | Path,
    policy_file: str | Path,
    opa_url: str,
    number_of_tests: int,
    output_file_path: str,
    is_stateless: bool,
    repetitions: int = 1,
    seed: Optional[int] = None,
):
    """
    Generate OPA tests, resolve their expected authorization using
    AuthorizationResolver, execute them against OPA, and compare
    expected vs actual decisions.

    Workflow:

        generate_opa_tests()
                |
                v
        AuthorizationResolver
                |
                v
        OPA execution
                |
                v
        expected vs actual

    Parameters
    ----------
    action_permissions_file:
        JSON mapping actions to required permissions.

    data_mesh_file:
        JSON describing the physical Data Mesh.

    users_file:
        JSON containing users and their security groups.

    permission_depth_file:
        JSON mapping permissions to hierarchy depths.

    policy_file:
        Canonical hierarchical authorization policy.

    opa_url:
        Full OPA decision URL.

    number_of_tests:
        Number of random tests to generate.

    output_file_path:
        File where the result will be written

    repetitions:
        Number of times each generated test is sent to OPA.

    seed:
        Optional random seed.

    """

    # ============================================================
    # 1. GENERATE TESTS
    # ============================================================
    print()
    print("=" * 70)
    print(" GENERATING OPA TESTS")
    print("=" * 70)
    tests = generate_opa_tests( action_permissions_file=action_permissions_file, data_mesh_file=data_mesh_file, users_file=users_file, permission_depth_file=permission_depth_file, number_of_tests=number_of_tests, seed=seed)
    print( f"Generated tests: {len(tests)}" )

    # ============================================================
    # 2. CREATE AUTHORIZATION RESOLVER
    # ============================================================
    resolver = AuthorizationResolver( policy_file=policy_file)

    # ============================================================
    # 3. RESOLVE + EXECUTE
    # ============================================================
    results = []
    total_executions = ( len(tests) * repetitions )
    execution_number = 0
    print()
    print("=" * 70)
    print(" RESOLVING AND EXECUTING TESTS")
    print("=" * 70)

    for test in tests:

        # --------------------------------------------------------
        # Generated test information
        # --------------------------------------------------------
        test_id = test.get( "testId" )
        action = test.get( "action" )
        resource = test.get( "resource", {} )
        security_group = test.get( "securityGroup" )
        opa_input = test.get( "input" )

        # --------------------------------------------------------
        # Resolve expected authorization
        # --------------------------------------------------------
        resolved = resolver.resolve( security_group=security_group, action_or_permission=action, resource=resource)
        expected_allowed = resolved["actions"][action][ "allowed" ]

        # --------------------------------------------------------
        # Execute same generated OPA input
        # --------------------------------------------------------

        for repetition in range( 1, repetitions + 1 ):
            execution_number += 1
            start = time.perf_counter_ns()
            response = requests.post( opa_url, params={ "metrics": "true" }, json={ "input": opa_input }, timeout=30)
            elapsed_ns = ( time.perf_counter_ns() - start )
            response.raise_for_status()
            opa_response = response.json()

            # ----------------------------------------------------
            # Validate OPA response
            # ----------------------------------------------------

            if "result" not in opa_response:

                raise RuntimeError(
                    "OPA did not return a decision.\n"
                    f"URL: {opa_url}\n"
                    f"Test ID: {test_id}\n"
                    f"Action: {action}\n"
                    f"Security group: {security_group}\n"
                    f"Resource: "
                    f"{json.dumps(resource, indent=4)}\n"
                    f"Input:\n"
                    f"{json.dumps(opa_input, indent=4)}\n"
                    f"Response:\n"
                    f"{json.dumps(opa_response, indent=4)}"
                )

            # ----------------------------------------------------
            # Actual OPA result
            # ----------------------------------------------------
            opa_actual = opa_response["result"]

            # ----------------------------------------------------
            # OPA metrics
            # ----------------------------------------------------
            metrics = opa_response.get( "metrics", {} )

            # ----------------------------------------------------
            # Compare expected vs actual
            #
            # OPA authorization endpoint should normally return
            # a boolean for this decision.
            # ----------------------------------------------------
            matches = ( opa_actual == expected_allowed )

            # ----------------------------------------------------
            # Store result
            # ----------------------------------------------------

            result = {
                # ------------------------------------------------
                # Test identity
                # ------------------------------------------------
                "testId": test_id,
                "repetition": repetition,

                # ------------------------------------------------
                # Authorization request
                # ------------------------------------------------
                "securityGroup": security_group,
                "action": action,
                "resource":  resource,
                "resourcePath": resolved.get( "resourcePath" ),
                "resourceType":  resolved.get( "resourceType" ),

                # ------------------------------------------------
                # Expected authorization
                # ------------------------------------------------
                "expectedAllowed": expected_allowed,
                "permissionResults": resolved["actions"][action].get( "permissionResults", {} ),
                "permissionDetails": resolved["actions"][action].get( "permissionDetails", {} ),
                "requiredPermissions": resolved["actions"][action].get( "requiredPermissions", [] ),

                # ------------------------------------------------
                # Actual OPA result
                # ------------------------------------------------
                "opaActual": opa_actual,
                "matches": matches,

                # ------------------------------------------------
                # Exact OPA input
                # ------------------------------------------------
                "input": opa_input,

                # ------------------------------------------------
                # Performance
                # ------------------------------------------------
                "httpLatencyNs": elapsed_ns,
                "opaEvalNs":  metrics.get( "timer_rego_query_eval_ns" ),
                "opaCompileNs": metrics.get( "timer_rego_query_compile_ns" ),
                "opaParseNs": metrics.get( "timer_rego_query_parse_ns" ),
                "regoHttpSendNs": metrics.get( "timer_rego_builtin_http_send_ns" ),
                "regoHttpRequests": metrics.get( "counter_rego_builtin_http_send_network_requests" ),
                "opaHandlerNs": metrics.get( "timer_server_handler_ns" ),
            }

            results.append( result )
            # ----------------------------------------------------
            # Progress
            # ----------------------------------------------------
            print( f"\rProgress: " f"{execution_number}/" f"{total_executions}", end="", flush=True)
    print()

    # ============================================================
    # SUMMARY
    # ============================================================
    correct = sum( 1 for result in results if result["matches"] )
    mismatches = len(results) - correct
    print()
    print("=" * 70)
    print(" OPA TEST RESULTS")
    print("=" * 70)
    print( f"Generated tests:       {len(tests)}" )
    print( f"OPA executions:        {len(results)}" )
    print( f"Correct decisions:     {correct}" )
    print( f"Decision mismatches:   {mismatches}" )
    print("=" * 70)

    # ============================================================
    # SHOW MISMATCHES
    # ============================================================

    if mismatches:
        print()
        print("=" * 70)
        print(" AUTHORIZATION MISMATCHES")
        print("=" * 70)
        for result in results:
            if result["matches"]:
                continue
            print()
            print( f"Test {result['testId']} " f"(repetition {result['repetition']})")
            print( f"  Security group: " f"{result['securityGroup']}" )
            print( f"  Action: " f"{result['action']}" )
            print( f"  Resource: " f"{result['resourcePath']}" )
            print( f"  Expected: " f"{result['expectedAllowed']}" )
            print( f"  OPA actual: " f"{result['opaActual']}" )
            print( "  Permission results:" )
            print( json.dumps( result["permissionResults"], indent=4 ) )
    path = Path(output_file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=2, ensure_ascii=False)
        file.write("\n")
    return

if __name__ == "__main__":
    print("=" * 60)
    print("ANALYSIS STATEFUL AND STATELESS OPA")
    print("=" * 60)
    NUMBER_OF_TEST = 10
    REPETITIONS = 5
    SEED = 42

    # ============================================================
    # 1. COPY ANALYSIS DATA
    # ============================================================
    source_analysis = Path( DATA_JSON_EXAMPLE_ANALYSIS )
    stateless_analysis = Path( DATA_STATELESS_PATH )
    stateful_analysis = Path( DATA_STATEFUL_PATH )
    stateless_analysis.parent.mkdir( parents=True, exist_ok=True)
    stateful_analysis.parent.mkdir( parents=True, exist_ok=True)
    shutil.copy2( source_analysis, stateless_analysis)
    shutil.copy2( source_analysis, stateful_analysis)
    print( f"Copied analysis data to:\n" f"  Stateless: {stateless_analysis}\n" f"  Stateful:  {stateful_analysis}" )

    # ============================================================
    # 2. GENERATE TESTS ONCE
    # ============================================================
    print()
    print("=" * 100)
    print("GENERATING BASE TESTS")
    print("=" * 100)
    tests = generate_opa_tests( action_permissions_file=CHECK_FOR_ACTION_PATH, data_mesh_file=DATA_MESH_STRUCTURE_PATH, users_file=USER_CREDENTIALS_PATH, permission_depth_file=PERMISSION_DEPTH_PATH, number_of_tests=NUMBER_OF_TEST, seed=SEED)
    print(f"Generated base tests: {len(tests)}")

    # ============================================================
    # 3. STOP OPA INSTANCES
    # ============================================================

    stop_docker_opa( STATEFUL_OPA_DOCKER_DIR )
    stop_docker_opa(STATELESS_OPA_DOCKER_DIR)

    # ============================================================
    # 4. STATEFUL
    # ============================================================

    print()
    print("=" * 100)
    print("\t\tANALYSIS STATEFUL")
    print("=" * 100)
    start_docker_opa( STATEFUL_OPA_DOCKER_DIR, STATEFUL_PORT)
    try:
        run_opa_tests(  tests=tests, action_permissions_file=CHECK_FOR_ACTION_PATH, policy_file=DATA_STATEFUL_PATH, opa_url=OPA_URL_STATEFUL, output_file_path=OUTPUT_STATEFUL_PATH, is_stateless=False,repetitions=REPETITIONS, )
    finally:
        stop_docker_opa(STATEFUL_OPA_DOCKER_DIR)

    # ============================================================
    # 5. STATELESS
    # ============================================================

    print()
    print("=" * 100)
    print("\t\tANALYSIS STATELESS")
    print("=" * 100)
    start_docker_opa( STATELESS_OPA_DOCKER_DIR, STATELESS_PORT)
    try:
        run_opa_tests(tests=tests, action_permissions_file=CHECK_FOR_ACTION_PATH, policy_file=DATA_STATELESS_PATH, opa_url=OPA_URL_STATELESS,  output_file_path=OUTPUT_STATELESS_PATH,  is_stateless=True, repetitions=REPETITIONS,)
    finally:
        stop_docker_opa( STATELESS_OPA_DOCKER_DIR )
