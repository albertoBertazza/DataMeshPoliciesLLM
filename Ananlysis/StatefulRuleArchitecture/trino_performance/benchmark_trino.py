# from pathlib import Path
# import os
#
# from TreePermission.tree_builder import build_permission_tree_from_directory
# from StatefulRuleArchitecture.trino_performance.generate_tests import generate_tests
# from StatefulRuleArchitecture.trino_performance.run_trino_tests import run_tests
#
#
# # Set to None to generate every possible test.
# MAX_TESTS = 20
#
#
#
# def benchmark_stateful_architecture(max_test):
#
#     print()
#     print("=" * 70)
#     print(" TRINO POLICY BENCHMARK")
#     print("=" * 70)
#
#     build_permission_tree_from_directory(OPA_FILE_PATH, CHECK_FOR_ACTION_PATH, SECURITY_GROUPS_PATH, OUTPUT_PATH)
#
#     generate_tests(
#         max_tests=max_test
#     )
#
#     run_tests()
#
#
# # ---------------------------------------------------------------------------
# # Main
# # ---------------------------------------------------------------------------
#
# if __name__ == "__main__":
#
#     benchmark_stateful_architecture(MAX_TESTS)