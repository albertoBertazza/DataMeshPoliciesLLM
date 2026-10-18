import json
import time
from pathlib import Path
from typing import Any, Dict, List

import requests

from Helper.action_resolver import AuthorizationResolver

def run_opa_tests( tests: List[Dict[str, Any]], action_permissions_file: str | Path, policy_file: str | Path, opa_url: str, output_file_path: str | Path, is_mapping_agnostic: bool, repetitions: int = 1, is_default_allowed: bool = False ):
    """
    Execute already-generated tests against OPA.

    The tests are generated only once by generate_opa_tests().

    Mapping Aware:
        One OPA execution per generated action test.

        operation = action

    Mapping Agnostic:
        The same generated action test is checked against every
        permission required by that action.

        The permission order is exactly the order in
        action_permissions.json.

        If one permission does not match the expected result,
        the remaining permissions of that action test are skipped.
    """

    # ============================================================
    # LOAD ACTION -> PERMISSION MAPPING ONCE
    # ============================================================

    with Path(action_permissions_file).open( "r", encoding="utf-8") as file:
        action_permissions = json.load(file)


    # ============================================================
    # EXECUTION
    # ============================================================

    results = []

    execution_number = 0

    # This is only an upper-bound progress value.
    if is_mapping_agnostic:

        total_possible_executions = sum( len(action_permissions.get(test["action"], [])) for test in tests ) * repetitions

    else:

        total_possible_executions = ( len(tests) * repetitions )

    print()
    print("=" * 70)

    if is_mapping_agnostic:
        print(" MAPPING AGNOSTIC OPA - PERMISSION TESTS")
    else:
        print(" MAPPING AWARE OPA - ACTION TESTS")

    print("=" * 70)

    print( f"Generated base tests: " f"{len(tests)}" )

    print( f"Maximum possible executions: " f"{total_possible_executions}" )

    # ============================================================
    # EACH GENERATED TEST IS USED ONCE
    # ============================================================

    for test in tests:

        test_id = test["testId"]

        action = test["action"]

        resource = test.get( "resource", {} )

        security_group = test["securityGroup"]

        original_input = test["input"]

        # ========================================================
        # DETERMINE OPERATIONS
        # ========================================================

        if is_mapping_agnostic:

            operations = action_permissions.get( action )

            if operations is None:

                raise ValueError( f"Action '{action}' has no permission mapping." )

        else:

            operations = [action]

        # ========================================================
        # CHECK PERMISSIONS IN EXACT ORDER
        # ========================================================

        for permission_index, operation in enumerate( operations ):

            # ----------------------------------------------------
            # Construct OPA input for this operation
            # ----------------------------------------------------

            opa_input = json.loads( json.dumps(original_input) )

            opa_input["action"]["operation"] = operation

            # ----------------------------------------------------
            # Resolve expected authorization
            # ----------------------------------------------------

            resolved = None
            if not is_default_allowed:
                # ============================================================
                # CREATE RESOLVER
                # ============================================================

                resolver = AuthorizationResolver(policy_file=policy_file, action_permissions_file=action_permissions_file)
                resolved = resolver.resolve( security_group=security_group, action_or_permission=operation, resource=resource)
            else :
                resolved = {
                    "operations": {
                        operation: {
                            "allowed": True,
                            "permissionResults": {},
                            "permissionDetails": {}
                        }
                    },
                }

            expected_operation = resolved[ "operations" ][operation]

            expected_allowed = ( expected_operation["allowed"] )

            # ----------------------------------------------------
            # Repetitions
            # ----------------------------------------------------

            permission_failed = False

            for repetition in range( 1, repetitions + 1):

                execution_number += 1

                # =================================================
                # SEND REQUEST TO OPA
                # =================================================

                start = time.perf_counter_ns()

                response = requests.post( opa_url, params={ "metrics": "true" }, json={ "input": opa_input }, timeout=30)

                elapsed_ns = ( time.perf_counter_ns() - start )

                response.raise_for_status()

                opa_response = response.json()

                # =================================================
                # VALIDATE RESPONSE
                # =================================================

                if "result" not in opa_response:

                    raise RuntimeError(
                        "OPA did not return a decision.\n"
                        f"URL: {opa_url}\n"
                        f"Test ID: {test_id}\n"
                        f"Action: {action}\n"
                        f"Operation: {operation}\n"
                        f"Security group: {security_group}\n"
                        f"Resource: "
                        f"{json.dumps(resource, indent=4)}\n"
                        f"Input:\n"
                        f"{json.dumps(opa_input, indent=4)}\n"
                        f"Response:\n"
                        f"{json.dumps(opa_response, indent=4)}"
                    )

                # =================================================
                # ACTUAL OPA RESULT
                # =================================================

                opa_actual = opa_response[ "result" ]

                # =================================================
                # METRICS
                # =================================================

                metrics = opa_response.get( "metrics", {} )

                # =================================================
                # COMPARE
                # =================================================

                matches = ( opa_actual == expected_allowed )

                # =================================================
                # SAVE RESULT
                # =================================================

                result = {

                    # -------------------------------
                    # Base test
                    # -------------------------------

                    "testId":
                        test_id,

                    "repetition":
                        repetition,

                    "securityGroup":
                        security_group,

                    # The original action.
                    "action":
                        action,

                    # The operation actually sent to OPA.
                    "operation":
                        operation,

                    # Permission index only matters
                    # for mapping agnostic execution.
                    "permissionIndex":
                        permission_index
                        if is_mapping_agnostic
                        else None,

                    "resource":
                        resource,

                    "resourcePath":
                        resolved.get( "resourcePath" ),

                    "resourceType":
                        resolved.get( "resourceType" ),

                    # -------------------------------
                    # Expected
                    # -------------------------------

                    "expectedAllowed":
                        expected_allowed,

                    "permissionResults":
                        expected_operation.get( "permissionResults", {}),

                    "permissionDetails":
                        expected_operation.get( "permissionDetails", {}),

                    # -------------------------------
                    # Actual
                    # -------------------------------

                    "opaActual":
                        opa_actual,

                    "matches":
                        matches,

                    # -------------------------------
                    # Input
                    # -------------------------------

                    "input":
                        opa_input,

                    # -------------------------------
                    # Performance
                    # -------------------------------

                    "httpLatencyNs":
                        elapsed_ns,

                    "opaEvalNs":
                        metrics.get( "timer_rego_query_eval_ns" ),

                    "opaCompileNs":
                        metrics.get( "timer_rego_query_compile_ns" ),

                    "opaParseNs":
                        metrics.get( "timer_rego_query_parse_ns" ),

                    "regoHttpSendNs":
                        metrics.get( "timer_rego_builtin_http_send_ns" ),

                    "regoHttpRequests":
                        metrics.get( "counter_rego_builtin_http_send_network_requests" ),

                    "opaHandlerNs":
                        metrics.get( "timer_server_handler_ns" ),
                }

                results.append(result)

                print( f"\rProgress: " f"{execution_number}/" f"{total_possible_executions}", end="", flush=True)

                # =================================================
                # MAPPING AGNOSTIC FAILURE
                # =================================================

                if is_mapping_agnostic and not matches:

                    permission_failed = True

                    break

            # ====================================================
            # SKIP REMAINING PERMISSIONS
            # ====================================================

            if is_mapping_agnostic and permission_failed:

                print()

                print( f"Test {test_id}: " f"operation '{operation}' failed. " f"Skipping remaining permissions." )

                break

    print()

    # ============================================================
    # SUMMARY
    # ============================================================

    correct = sum( 1 for result in results if result["matches"] )

    mismatches = ( len(results) - correct )

    print()
    print("=" * 70)

    if is_mapping_agnostic:
        print(" MAPPING AGNOSTIC OPA TEST RESULTS")
    else:
        print(" MAPPING AWARE OPA TEST RESULTS")

    print("=" * 70)

    print( f"Generated base tests: " f"{len(tests)}" )

    print( f"OPA executions: " f"{len(results)}" )

    print( f"Correct decisions: " f"{correct}" )

    print( f"Decision mismatches: " f"{mismatches}" )

    print("=" * 70)

    # ============================================================
    # MISMATCHES
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

            print( f"  Operation: " f"{result['operation']}" )

            print( f"  Resource: " f"{result['resourcePath']}" )

            print( f"  Expected: " f"{result['expectedAllowed']}" )

            print( f"  OPA actual: " f"{result['opaActual']}" )

            print( "  Permission details:" )

            print( json.dumps( result["permissionDetails"], indent=4) )

    # ============================================================
    # SAVE
    # ============================================================

    path = Path( output_file_path )

    path.parent.mkdir( parents=True, exist_ok=True)

    with path.open( "w", encoding="utf-8") as file:

        json.dump( results, file, indent=2, ensure_ascii=False)

        file.write("\n")

    return results
