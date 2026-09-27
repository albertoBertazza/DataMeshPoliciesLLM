from typing import Any, Dict, List
from Pipelines.B_TestAndEvaluationPipeline.A_TestGeneration.Resolver.authorization_resolver import ( AuthorizationResolver)
from Pipelines.B_TestAndEvaluationPipeline.A_TestGeneration.TrinoTestGenerator import ( TrinoTestGenerator)
from Pipelines.B_TestAndEvaluationPipeline.B_TestExecution.run_test_trino import ( launch_test)
from Pipelines.costantPath import ( REWRITTEN_RULE_PATH, GENERATED_RULE_PATH, ACTION_SQL_MAPPING_PATH, USER_CREDENTIALS_PATH, DATA_MESH_STRUCTURE_PATH, CHECK_FOR_ACTION_PATH, OUTPUT_TEST_EXECUTION_FILE)

def explain_authorization_failure( action_result: Dict[str, Any]) -> Dict[str, Any]:
    permission_results = action_result.get( "permissionResults", {})
    permission_details = action_result.get( "permissionDetails", {})
    denied_permissions = []
    allowed_permissions = []
    for permission, result in permission_results.items():
        details = permission_details.get( permission, {})
        if result is False:
            denied_permissions.append( { "permission": permission, "decision": details.get( "decision", "DENY"), "deniedAt": details.get( "deniedAt", []), "declarations": details.get( "declarations", [])} )
        elif result is True:
            allowed_permissions.append( { "permission": permission, "decision": details.get( "decision", "ALLOW"), "allowedAt": details.get( "allowedAt", [])} )
    return { "requiredPermissions": action_result.get( "requiredPermissions", []), "deniedPermissions": denied_permissions, "allowedPermissions": allowed_permissions}

def execute_test(test: Dict[str, Any]) -> bool:
    """
    Execute exactly one generated Trino test.
    """
    report = launch_test( test=test, test_path=OUTPUT_TEST_EXECUTION_FILE )
    results = report.get( "results", [] )
    if not results:
        raise RuntimeError( "Trino test execution produced no result." )
    return bool( results[0] .get("output", {}) .get("actual_allowed", False) )

def testEvaluation() -> Dict[str, Any]:
    # =========================================================
    # 1. CREATE RESOLVER
    # =========================================================
    resolver = AuthorizationResolver( REWRITTEN_RULE_PATH, GENERATED_RULE_PATH, CHECK_FOR_ACTION_PATH)

    # =========================================================
    # 2. CREATE TEST GENERATOR
    # =========================================================
    test_generator = TrinoTestGenerator( USER_CREDENTIALS_PATH, DATA_MESH_STRUCTURE_PATH, ACTION_SQL_MAPPING_PATH)

    # =========================================================
    # 3. RESOLVE
    # =========================================================
    resolved = resolver.resolve()

    # =========================================================
    # 4. GENERATE TESTS
    # =========================================================
    generated_tests = test_generator.generate( resolved )

    # =========================================================
    # 5. INDEX RESOLVER RESULTS
    # =========================================================
    resolved_index = {}
    for resource_result in resolved:
        security_group = resource_result.get( "securityGroup" )
        resource_path = resource_result.get( "resourcePath" )
        for action, action_result in resource_result.get( "actions", {}).items():
            key = ( security_group, resource_path, action)
            resolved_index[key] = action_result

    # =========================================================
    # 6. EXECUTE TESTS
    # =========================================================
    evaluations: List[Dict[str, Any]] = []
    passed = 0
    failed = 0
    for test in generated_tests:
        security_group = test.get( "securityGroup" )
        resource_path = test.get( "resourcePath" )
        action = test.get( "action" )
        key = ( security_group, resource_path, action)
        resolved_action = resolved_index.get( key )

        # -----------------------------------------------------
        # Resolver result missing
        # -----------------------------------------------------
        if resolved_action is None:
            evaluations.append( { "status": "FAIL", "reason": "resolver_result_not_found", "securityGroup": security_group, "resourcePath": resource_path, "action": action, "test": test} )
            failed += 1
            continue

        # -----------------------------------------------------
        # Expected resolver result
        # -----------------------------------------------------
        expected_allowed = bool( resolved_action.get( "allowed", False) )

        # -----------------------------------------------------
        # Actual Trino result
        # -----------------------------------------------------
        try:
            actual_allowed = execute_test( test )
        except Exception as exc:
            evaluations.append( { "status": "FAIL", "reason": "test_execution_error", "error": str(exc), "securityGroup": security_group, "resourcePath": resource_path, "action": action, "query": test.get("query"), "expected": expected_allowed} )
            failed += 1
            continue

        # -----------------------------------------------------
        # Compare
        # -----------------------------------------------------
        matches = ( expected_allowed == actual_allowed )
        evaluation = { "securityGroup": security_group, "resourcePath": resource_path, "action": action, "resource": test.get( "resource", {}), "query": test.get( "query" ), "expected": expected_allowed, "actual": actual_allowed, "match": matches}

        # -----------------------------------------------------
        # PASS
        # -----------------------------------------------------
        if matches:
            evaluation["status"] = "PASS"
            passed += 1

        # -----------------------------------------------------
        # FAIL
        # -----------------------------------------------------
        else:
            evaluation["status"] = "FAIL"
            evaluation["failure"] = ( explain_authorization_failure( resolved_action ) )
            if ( expected_allowed is True and actual_allowed is False ):
                evaluation["failureType"] = ( "EXPECTED_ALLOW_BUT_TRINO_DENIED" )
            elif ( expected_allowed is False and actual_allowed is True ):
                evaluation["failureType"] = ( "EXPECTED_DENY_BUT_TRINO_ALLOWED" )
            else:
                evaluation["failureType"] = ( "AUTHORIZATION_MISMATCH" )
            failed += 1
        evaluations.append( evaluation )

    # =========================================================
    # 7. RETURN REPORT
    # =========================================================

    return { "summary": { "total": len(evaluations), "passed": passed, "failed": failed, "success": failed == 0}, "resolvedCount": len(resolved), "generatedTestCount": len(generated_tests), "evaluations": evaluations}
