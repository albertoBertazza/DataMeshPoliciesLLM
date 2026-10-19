import json
import random
from pathlib import Path
from typing import Any, Dict, List, Optional

from Helper.input_builder import build_opa_input

OBLIGATION_PERMISSIONS = { "GetColumnMask", "GetRowFilters"}

def generate_opa_tests( action_permissions_file: str | Path, data_mesh_file: str | Path, users_file: str | Path, permission_depth_file: str | Path, number_of_tests: int, seed: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Generate random OPA test inputs.

    Parameters
    ----------
    action_permissions_file:
        JSON mapping actions to required permissions.

    data_mesh_file:
        JSON describing physical catalogs, schemas, tables and columns.

    users_file:
        JSON list of users and their security groups.

    permission_depth_file:
        JSON mapping permissions to hierarchy depths.

    number_of_tests:
        Number of tests to generate.

    seed:
        Optional random seed for reproducibility.

    Returns
    -------
    list
        Generated OPA inputs.
    """

    if number_of_tests <= 0:
        return []

    if seed is not None:
        random.seed(seed)

    # ------------------------------------------------------------
    # Load files
    # ------------------------------------------------------------

    def load_json(path: str | Path):
        with Path(path).open("r", encoding="utf-8") as f:
            return json.load(f)

    action_permissions = load_json(action_permissions_file)
    data_mesh = load_json(data_mesh_file)
    users = load_json(users_file)
    permission_depth = load_json(permission_depth_file)
    permission_depth = permission_depth.get("permission_depth", {})

    # ------------------------------------------------------------
    # Extract security groups
    # ------------------------------------------------------------
    security_groups = sorted({ group for user in users for group in user.get("groups", []) if group })
    if not security_groups:
        raise ValueError( "No security groups were found in the users file." )
    # ------------------------------------------------------------
    # Flatten the data mesh
    #
    # Each entry represents one possible authorization target.
    #
    # depth 1 -> catalog
    # depth 2 -> schema
    # depth 3 -> table
    # depth 4 -> column
    # ------------------------------------------------------------
    resources_by_depth = { 0: [ { "catalog": None, "schema": None, "table": None, "column": None} ], 1: [], 2: [], 3: [], 4: []}
    for catalog in data_mesh.get("catalogs", []):
        catalog_name = catalog.get("name")
        if not catalog_name:
            continue
        resources_by_depth[1].append({ "catalog": catalog_name, "schema": None, "table": None, "column": None})
        for schema in catalog.get("schemas", []):
            schema_name = schema.get("name")
            if not schema_name:
                continue
            resources_by_depth[2].append({ "catalog": catalog_name, "schema": schema_name, "table": None, "column": None})
            for table in schema.get("tables", []):
                table_name = table.get("name")
                if not table_name:
                    continue
                resources_by_depth[3].append({ "catalog": catalog_name, "schema": schema_name, "table": table_name, "column": None})
                for column in table.get("columns", []):
                    column_name = column.get("name")
                    if not column_name:
                        continue
                    resources_by_depth[4].append({ "catalog": catalog_name, "schema": schema_name, "table": table_name, "column": column_name})

    # ------------------------------------------------------------
    # Determine the target depth of an action
    # ------------------------------------------------------------

    def get_action_depth(action: str) -> int:
        """
        Determine the resource depth required by an action.

        Obligation permissions are ignored because they describe
        row filters / column masks rather than the action target.

        The most specific remaining permission determines the
        action target depth.
        """
        permissions = action_permissions.get(action)
        if not permissions:
            raise ValueError( f"Action '{action}' has no permission mapping." )
        depths = []
        for permission in permissions:
            if permission in OBLIGATION_PERMISSIONS:
                continue
            if permission not in permission_depth:
                raise ValueError( f"Permission '{permission}' used by action " f"'{action}' is missing from permission_depth." )
            depths.append(permission_depth[permission])
        if not depths:
            # This should only happen if an action consists entirely
            # of obligation permissions.
            raise ValueError( f"Action '{action}' contains no non-obligation " f"permissions from which a target depth can be derived." )
        return max(depths)

    # ------------------------------------------------------------
    # Generate tests
    # ------------------------------------------------------------
    actions = list(action_permissions.keys())
    if not actions:
        raise ValueError( "No actions were found in the action-permissions file." )
    tests = []
    for test_id in range(1, number_of_tests + 1):
        # --------------------------------------------------------
        # 1. Random action
        # --------------------------------------------------------
        action = random.choice(actions)

        # --------------------------------------------------------
        # 2. Determine required resource depth
        # --------------------------------------------------------
        depth = get_action_depth(action)
        possible_resources = resources_by_depth.get(depth, [])
        if not possible_resources:
            raise ValueError( f"No resources exist in the Data Mesh at depth " f"{depth}, required by action '{action}'." )

        # --------------------------------------------------------
        # 3. Random physical resource
        # --------------------------------------------------------
        resource = random.choice(possible_resources).copy()

        # --------------------------------------------------------
        # 4. Random security group
        # --------------------------------------------------------
        security_group = random.choice(security_groups)

        # --------------------------------------------------------
        # 5. Build operation
        #
        # The Rego input expects ONE operation:
        #
        # input.action.operation
        #
        # Since the action maps to several permissions, the normal
        # operation used for the test must be the action itself's
        # Trino operation.
        #
        # Here we keep the action as operation unless you provide
        # a separate action -> operation mapping.
        # --------------------------------------------------------
        operation = action

        # --------------------------------------------------------
        # 6. Build OPA input
        # --------------------------------------------------------
        opa_input = build_opa_input( resource=resource, operation=operation, security_group=security_group)

        # --------------------------------------------------------
        # 7. Add metadata useful for evaluation/debugging
        # --------------------------------------------------------

        tests.append({ "testId": test_id, "action": action, "resourceDepth": depth, "resource": resource, "securityGroup": security_group, "input": opa_input})

    return tests

'''
tests = generate_opa_tests(
    action_permissions_file=r"C:action_permissions.json",
    data_mesh_file=r"C:data_mesh.json",
    users_file=r"C:users.json",
    permission_depth_file=r"C:permission_depth.json",
    number_of_tests=20,
    seed=42,
)

for test in tests:
    print(json.dumps(test, indent=2))

'''
