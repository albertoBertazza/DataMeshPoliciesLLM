from typing import Any, Dict, List

from Pipelines.B_TestAndEvaluationPipeline.A_TestGeneration.Resolver.authorization_resolver import (
    AuthorizationResolver,
)


def explain_authorization_failure(
    action_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Explain why the resolver produced its authorization result.

    Particularly useful when:

        expected = ALLOW
        actual   = DENY

    because it identifies the required permission(s) that caused
    the action to be denied and their declarations.
    """

    permission_results = action_result.get(
        "permissionResults",
        {},
    )

    permission_details = action_result.get(
        "permissionDetails",
        {},
    )

    denied_permissions = []
    allowed_permissions = []

    for permission, result in permission_results.items():

        details = permission_details.get(
            permission,
            {},
        )

        if result is False:

            denied_permissions.append(
                {
                    "permission": permission,
                    "decision": details.get(
                        "decision",
                        "DENY",
                    ),
                    "deniedAt": details.get(
                        "deniedAt",
                        [],
                    ),
                    "declarations": details.get(
                        "declarations",
                        [],
                    ),
                }
            )

        elif result is True:

            allowed_permissions.append(
                {
                    "permission": permission,
                    "decision": details.get(
                        "decision",
                        "ALLOW",
                    ),
                    "allowedAt": details.get(
                        "allowedAt",
                        [],
                    ),
                }
            )

    return {
        "requiredPermissions": action_result.get(
            "requiredPermissions",
            [],
        ),
        "deniedPermissions": denied_permissions,
        "allowedPermissions": allowed_permissions,
    }


def testEvaluation(
    resolver,
    test_generator,
    execute_test,
) -> Dict[str, Any]:
    """
    End-to-end authorization evaluation.

    1. Resolve authorization.
    2. Generate SQL tests from the resolved actions.
    3. Execute each SQL test.
    4. Compare resolver expectation with Trino outcome.
    5. Explain mismatches using permissionDetails / permissionResults.

    Parameters
    ----------
    resolver:
        AuthorizationResolver instance.

    test_generator:
        Trino test generator instance.

    execute_test:
        Callable receiving one generated test and returning the actual
        authorization result as a boolean.

        Example:
            execute_test(test) -> True
            execute_test(test) -> False

    Returns
    -------
    Dict[str, Any]
        Evaluation report.
    """

    # =========================================================
    # 1. RESOLVE AUTHORIZATION
    # =========================================================

    resolved = resolver.resolve()

    # =========================================================
    # 2. GENERATE TESTS
    # =========================================================

    generated_tests = test_generator.generate(
        resolved
    )

    # =========================================================
    # 3. INDEX RESOLVER RESULTS
    # =========================================================

    resolved_index = {}

    for resource_result in resolved:

        security_group = resource_result.get(
            "securityGroup"
        )

        resource_path = resource_result.get(
            "resourcePath"
        )

        actions = resource_result.get(
            "actions",
            {},
        )

        for action, action_result in actions.items():

            key = (
                security_group,
                resource_path,
                action,
            )

            resolved_index[key] = action_result

    # =========================================================
    # 4. EXECUTE AND COMPARE
    # =========================================================

    evaluations: List[Dict[str, Any]] = []

    passed = 0
    failed = 0

    for test in generated_tests:

        security_group = test.get(
            "securityGroup"
        )

        resource_path = test.get(
            "resourcePath"
        )

        action = test.get(
            "action"
        )

        key = (
            security_group,
            resource_path,
            action,
        )

        resolved_action = resolved_index.get(
            key
        )

        # -----------------------------------------------------
        # Resolver result cannot be found
        # -----------------------------------------------------

        if resolved_action is None:

            evaluations.append(
                {
                    "status": "FAIL",
                    "reason": "resolver_result_not_found",
                    "securityGroup": security_group,
                    "resourcePath": resource_path,
                    "action": action,
                    "test": test,
                }
            )

            failed += 1
            continue

        # -----------------------------------------------------
        # Expected result from resolver
        # -----------------------------------------------------

        expected_allowed = bool(
            resolved_action.get(
                "allowed",
                False,
            )
        )

        # -----------------------------------------------------
        # Actual result from Trino
        # -----------------------------------------------------

        try:

            actual_allowed = execute_test(
                test
            )

            if isinstance(actual_allowed, dict):

                if "actual_allowed" in actual_allowed:

                    actual_allowed = bool(
                        actual_allowed[
                            "actual_allowed"
                        ]
                    )

                elif "allowed" in actual_allowed:

                    actual_allowed = bool(
                        actual_allowed[
                            "allowed"
                        ]
                    )

                else:

                    actual_allowed = bool(
                        actual_allowed
                    )

            else:

                actual_allowed = bool(
                    actual_allowed
                )

        except Exception as exc:

            evaluations.append(
                {
                    "status": "FAIL",
                    "reason": "test_execution_error",
                    "securityGroup": security_group,
                    "resourcePath": resource_path,
                    "action": action,
                    "query": test.get("query"),
                    "expected": expected_allowed,
                    "error": str(exc),
                    "test": test,
                }
            )

            failed += 1
            continue

        # -----------------------------------------------------
        # Compare resolver and Trino
        # -----------------------------------------------------

        matches = (
            expected_allowed
            == actual_allowed
        )

        evaluation = {
            "securityGroup": security_group,
            "resourcePath": resource_path,
            "action": action,
            "resource": test.get(
                "resource",
                {},
            ),
            "query": test.get(
                "query"
            ),
            "expected": expected_allowed,
            "actual": actual_allowed,
            "match": matches,
        }

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

            evaluation["failure"] = (
                explain_authorization_failure(
                    resolved_action
                )
            )

            if (
                expected_allowed is True
                and actual_allowed is False
            ):

                evaluation["failureType"] = (
                    "EXPECTED_ALLOW_BUT_TRINO_DENIED"
                )

            elif (
                expected_allowed is False
                and actual_allowed is True
            ):

                evaluation["failureType"] = (
                    "EXPECTED_DENY_BUT_TRINO_ALLOWED"
                )

            else:

                evaluation["failureType"] = (
                    "AUTHORIZATION_MISMATCH"
                )

            failed += 1

        evaluations.append(
            evaluation
        )

    # =========================================================
    # 5. SUMMARY
    # =========================================================

    return {
        "summary": {
            "total": len(evaluations),
            "passed": passed,
            "failed": failed,
            "success": failed == 0,
        },
        "resolvedCount": len(resolved),
        "generatedTestCount": len(generated_tests),
        "evaluations": evaluations,
    }
