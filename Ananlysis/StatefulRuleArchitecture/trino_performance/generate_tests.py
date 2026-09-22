import json
import random
from datetime import datetime
import os
from pathlib import Path

from TreePermission.tree_builder import build_permission_tree_from_directory
from TreePermission.TreeResolver.tree_resolver import PermissionTreeResolver

from Pipelines.costantPath import CHECK_FOR_ACTION_PATH, SECURITY_GROUPS_PATH

# ============================================================================
# Configuration
# ============================================================================

SELECT_LIMIT = 5

# Set to None to generate every possible test.
MAX_TESTS = None

# Used only when MAX_TESTS is not None.
TARGET_ALLOWED_RATIO = 0.50

# Reproducible randomization.
RANDOM_SEED = 42


# ============================================================================
# Paths
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent

STATEFULL_RULE_ARCHITECTURE_DIR = BASE_DIR.parent

PROJECT_DIR = STATEFULL_RULE_ARCHITECTURE_DIR.parent

TREE_PATH = (
    STATEFULL_RULE_ARCHITECTURE_DIR
    / "trino_performance"
    / "tree_permission"
    / "tree.json"
)

DATA_MESH_PATH = (
    PROJECT_DIR
    / "LLM"
    / "Structure"
    / "data_mesh.json"
)

GENERATED_DIR = BASE_DIR / "generated"

OUTPUT_FILE = GENERATED_DIR / "trino_tests.json"


# ============================================================================
# SQL generation
# ============================================================================

def build_sql(action, catalog, schema, table):
    """
    Convert an action into executable Trino SQL.

    Only actions with a known SQL representation are generated.
    """

    if action == "SelectFromTableAction":
        return f"SELECT * FROM {catalog}.{schema}.{table} LIMIT {SELECT_LIMIT}"

    if action == "ShowTablesAction":
        return f"SHOW TABLES FROM {catalog}.{schema}"

    if action == "ShowSchemasAction":
        return f"SHOW SCHEMAS FROM {catalog}"

    return None


# ============================================================================
# Load tree
# ============================================================================

def load_tree():

    if not TREE_PATH.exists():
        raise FileNotFoundError(
            f"tree.json not found:\n{TREE_PATH}"
        )

    with TREE_PATH.open("r", encoding="utf-8") as file:
        tree = json.load(file)

    if not isinstance(tree, dict):
        raise ValueError("tree.json must contain a JSON object")

    if "ROOT" not in tree:
        raise ValueError("tree.json must contain a ROOT node")

    if not isinstance(tree["ROOT"], dict):
        raise ValueError("tree.json ROOT must be an object")

    return tree


# ============================================================================
# Load Data Mesh
# ============================================================================

def load_data_mesh():

    if not DATA_MESH_PATH.exists():
        raise FileNotFoundError(
            f"data_mesh.json not found:\n{DATA_MESH_PATH}"
        )

    with DATA_MESH_PATH.open("r", encoding="utf-8") as file:
        data_mesh = json.load(file)

    if not isinstance(data_mesh, dict):
        raise ValueError(
            "data_mesh.json must contain a JSON object"
        )

    return data_mesh


# ============================================================================
# Data Mesh resources
# ============================================================================

def collect_data_mesh_resources(data_mesh):
    """
    Return every concrete table defined in data_mesh.json.

    data_mesh.json is the authoritative source for physical resources.
    """

    resources = []

    catalogs = data_mesh.get("catalogs", [])

    if not isinstance(catalogs, list):
        return resources

    for catalog_node in catalogs:

        if not isinstance(catalog_node, dict):
            continue

        catalog = catalog_node.get("name")

        if not catalog:
            continue

        schemas = catalog_node.get("schemas", [])

        if not isinstance(schemas, list):
            continue

        for schema_node in schemas:

            if not isinstance(schema_node, dict):
                continue

            schema = schema_node.get("name")

            if not schema:
                continue

            tables = schema_node.get("tables", [])

            if not isinstance(tables, list):
                continue

            for table_node in tables:

                if not isinstance(table_node, dict):
                    continue

                table = table_node.get("name")

                if not table:
                    continue

                resources.append(
                    {
                        "catalog": catalog,
                        "schema": schema,
                        "table": table,
                    }
                )

    return resources


# ============================================================================
# Allowed tests
# ============================================================================

def generate_allowed_tests(
    resolver,
    data_mesh_resources,
    known_actions,
):
    """
    Generate tests for actions explicitly allowed by the permission tree.

    The permission tree determines authorization.
    data_mesh.json determines physical resources.
    """

    tests = []

    security_groups = resolver.security_groups()

    for mesh_resource in data_mesh_resources:

        catalog = mesh_resource["catalog"]
        schema = mesh_resource["schema"]
        table = mesh_resource["table"]

        for security_group in security_groups:

            for action in known_actions:

                sql = build_sql(
                    action=action,
                    catalog=catalog,
                    schema=schema,
                    table=table,
                )

                if sql is None:
                    continue

                result = resolver.resolve_action(
                    security_group=security_group,
                    catalog=catalog,
                    schema=schema,
                    table=table,
                    action=action,
                )

                if not result["allowed"]:
                    continue

                tests.append(
                    {
                        "security_group": security_group,
                        "action": action,
                        "catalog": catalog,
                        "schema": schema,
                        "table": table,
                        "sql": sql,
                        "expected_allowed": True,
                        "required_permissions": result.get(
                            "required_permissions",
                            [],
                        ),
                        "permission_source": result.get(
                            "source"
                        ),
                        "test_type": "allowed",
                    }
                )

    return tests


# ============================================================================
# Denied tests
# ============================================================================

def generate_denied_tests(
    resolver,
    data_mesh_resources,
    known_actions,
):
    """
    Generate tests for actions not allowed for a concrete
    security-group/resource combination.
    """

    tests = []

    security_groups = resolver.security_groups()

    for mesh_resource in data_mesh_resources:

        catalog = mesh_resource["catalog"]
        schema = mesh_resource["schema"]
        table = mesh_resource["table"]

        for security_group in security_groups:

            for action in known_actions:

                sql = build_sql(
                    action=action,
                    catalog=catalog,
                    schema=schema,
                    table=table,
                )

                if sql is None:
                    continue

                result = resolver.resolve_action(
                    security_group=security_group,
                    catalog=catalog,
                    schema=schema,
                    table=table,
                    action=action,
                )

                if result["allowed"]:
                    continue

                tests.append(
                    {
                        "security_group": security_group,
                        "action": action,
                        "catalog": catalog,
                        "schema": schema,
                        "table": table,
                        "sql": sql,
                        "expected_allowed": False,
                        "required_permissions": [],
                        "permission_source": result.get(
                            "source"
                        ),
                        "test_type": "denied",
                    }
                )

    return tests


# ============================================================================
# Deduplication
# ============================================================================

def deduplicate_tests(tests):

    unique = {}

    duplicates = 0

    for test in tests:

        key = (
            test["security_group"],
            test["action"],
            test["catalog"],
            test["schema"],
            test["table"],
            test["expected_allowed"],
        )

        if key in unique:
            duplicates += 1
            continue

        unique[key] = test

    return list(unique.values()), duplicates


# ============================================================================
# Balance
# ============================================================================

def balance_tests(allowed, denied, max_tests=None):

    random.seed(RANDOM_SEED)

    random.shuffle(allowed)
    random.shuffle(denied)

    if max_tests is None:

        result = allowed + denied

        random.shuffle(result)

        return result

    target_allowed = int(
        max_tests * TARGET_ALLOWED_RATIO
    )

    target_denied = max_tests - target_allowed

    selected_allowed = allowed[:target_allowed]

    selected_denied = denied[:target_denied]

    result = selected_allowed + selected_denied

    # Fill remaining slots if one category was too small.
    if len(result) < max_tests:

        remaining_allowed = allowed[len(selected_allowed):]

        remaining_denied = denied[len(selected_denied):]

        remaining = remaining_allowed + remaining_denied

        random.shuffle(remaining)

        needed = max_tests - len(result)

        result.extend(remaining[:needed])

    random.shuffle(result)

    return result


# ============================================================================
# IDs
# ============================================================================

def add_ids(tests):

    for index, test in enumerate(tests, start=1):
        test["id"] = f"test_{index:06d}"

    return tests


# ============================================================================
# Statistics
# ============================================================================

def print_generation_statistics(tests):

    allowed = sum(
        test["expected_allowed"]
        for test in tests
    )

    denied = sum(
        not test["expected_allowed"]
        for test in tests
    )

    security_groups = {
        test["security_group"]
        for test in tests
    }

    resources = {
        (
            test["catalog"],
            test["schema"],
            test["table"],
        )
        for test in tests
    }

    actions = {
        test["action"]
        for test in tests
    }

    test_types = {
        test["test_type"]
        for test in tests
    }

    permission_sources = {
        test.get("permission_source")
        for test in tests
    }

    print()
    print("=" * 70)
    print(" GENERATED TEST STATISTICS")
    print("=" * 70)

    print(f"Total tests:       {len(tests)}")
    print(f"Allowed:           {allowed}")
    print(f"Denied:            {denied}")
    print(f"Security groups:   {len(security_groups)}")
    print(f"Resources:         {len(resources)}")
    print(f"Actions:            {len(actions)}")

    print()

    print("Actions:")

    for action in sorted(actions):

        count = sum(
            test["action"] == action
            for test in tests
        )

        print(f"  {action}: {count}")

    print()

    print("Security groups:")

    for group in sorted(security_groups):

        count = sum(
            test["security_group"] == group
            for test in tests
        )

        print(f"  {group}: {count}")

    print()

    print("Resources:")

    for catalog, schema, table in sorted(resources):

        count = sum(
            test["catalog"] == catalog
            and test["schema"] == schema
            and test["table"] == table
            for test in tests
        )

        print(
            f"  {catalog}.{schema}.{table}: {count}"
        )

    print()

    print("Permission sources:")

    for source in sorted(
        str(source)
        for source in permission_sources
    ):

        count = sum(
            str(test.get("permission_source")) == source
            for test in tests
        )

        print(f"  {source}: {count}")

    print()

    print("Test types:")

    for test_type in sorted(test_types):

        count = sum(
            test["test_type"] == test_type
            for test in tests
        )

        print(f"  {test_type}: {count}")


# ============================================================================
# Tree inspection
# ============================================================================

def inspect_tree(tree):

    print()
    print("=" * 70)
    print(" TREE STRUCTURE")
    print("=" * 70)

    root = tree.get("ROOT", {})

    if not isinstance(root, dict):
        print("Invalid ROOT node")
        return

    print("\nROOT")
    print("  keys:", list(root.keys()))

    # ------------------------------------------------------------------------
    # ROOT security groups
    # ------------------------------------------------------------------------

    root_groups = root.get("security_groups", {})

    if isinstance(root_groups, dict):

        print("\n  ROOT SECURITY GROUPS:")

        for group_name, group_node in sorted(
            root_groups.items()
        ):

            print(f"    {group_name}")

            if not isinstance(group_node, dict):
                continue

            permissions = group_node.get(
                "permissions",
                [],
            )

            allowed_actions = group_node.get(
                "allowed_actions",
                [],
            )

            if permissions:
                print(
                    f"      permissions: {permissions}"
                )

            if allowed_actions:
                print(
                    f"      allowed_actions: {allowed_actions}"
                )

    # ------------------------------------------------------------------------
    # Catalogs
    # ------------------------------------------------------------------------

    catalogs = root.get("catalogs", {})

    if not isinstance(catalogs, dict):
        return

    for catalog_name, catalog_node in sorted(
        catalogs.items()
    ):

        if not isinstance(catalog_node, dict):
            continue

        print(f"\n  CATALOG: {catalog_name}")
        print(
            "    keys:",
            list(catalog_node.keys()),
        )

        catalog_groups = catalog_node.get(
            "security_groups",
            {},
        )

        if isinstance(catalog_groups, dict):

            print("    SECURITY GROUPS:")

            for group_name, group_node in sorted(
                catalog_groups.items()
            ):

                print(f"      {group_name}")

                if not isinstance(group_node, dict):
                    continue

                if group_node.get("permissions"):
                    print(
                        f"        permissions: "
                        f"{group_node['permissions']}"
                    )

                if group_node.get("allowed_actions"):
                    print(
                        f"        allowed_actions: "
                        f"{group_node['allowed_actions']}"
                    )

        # --------------------------------------------------------------------
        # Schemas
        # --------------------------------------------------------------------

        schemas = catalog_node.get(
            "schemas",
            {},
        )

        if not isinstance(schemas, dict):
            continue

        for schema_name, schema_node in sorted(
            schemas.items()
        ):

            if not isinstance(schema_node, dict):
                continue

            print(f"    SCHEMA: {schema_name}")
            print(
                "      keys:",
                list(schema_node.keys()),
            )

            schema_groups = schema_node.get(
                "security_groups",
                {},
            )

            if isinstance(schema_groups, dict):

                print("      SECURITY GROUPS:")

                for group_name, group_node in sorted(
                    schema_groups.items()
                ):

                    print(f"        {group_name}")

                    if not isinstance(group_node, dict):
                        continue

                    if group_node.get("permissions"):
                        print(
                            f"          permissions: "
                            f"{group_node['permissions']}"
                        )

                    if group_node.get("allowed_actions"):
                        print(
                            f"          allowed_actions: "
                            f"{group_node['allowed_actions']}"
                        )

            # ----------------------------------------------------------------
            # Tables
            # ----------------------------------------------------------------

            tables = schema_node.get(
                "tables",
                {},
            )

            if not isinstance(tables, dict):
                continue

            for table_name, table_node in sorted(
                tables.items()
            ):

                if not isinstance(table_node, dict):
                    continue

                print(f"      TABLE: {table_name}")
                print(
                    "        keys:",
                    list(table_node.keys()),
                )

                # ------------------------------------------------------------
                # Columns
                # ------------------------------------------------------------

                columns = table_node.get(
                    "columns",
                    {},
                )

                if not isinstance(columns, dict):
                    continue

                for column_name, column_node in sorted(
                    columns.items()
                ):

                    if not isinstance(column_node, dict):
                        continue

                    print(
                        f"        COLUMN: {column_name}"
                    )

                    column_groups = column_node.get(
                        "security_groups",
                        {},
                    )

                    if not isinstance(
                        column_groups,
                        dict,
                    ):
                        continue

                    for group_name, group_node in sorted(
                        column_groups.items()
                    ):

                        print(
                            f"          SECURITY GROUP: "
                            f"{group_name}"
                        )

                        if not isinstance(
                            group_node,
                            dict,
                        ):
                            continue

                        filters = group_node.get(
                            "filters",
                            {},
                        )

                        if filters:
                            print(
                                "            filters:",
                                json.dumps(
                                    filters,
                                    indent=2,
                                ),
                            )


# ============================================================================
# Main generation function
# ============================================================================

def generate_tests(max_tests=MAX_TESTS):

    print("=" * 70)
    print(" TRINO PERFORMANCE TEST GENERATOR")
    print("=" * 70)

    print(f"Tree:\n{TREE_PATH}")
    print(f"Data Mesh:\n{DATA_MESH_PATH}")

    tree = load_tree()

    data_mesh = load_data_mesh()

    # ------------------------------------------------------------------------
    # Resolver
    # ------------------------------------------------------------------------

    resolver = PermissionTreeResolver(tree)

    # ------------------------------------------------------------------------
    # Inspect tree
    # ------------------------------------------------------------------------

    inspect_tree(tree)

    # ------------------------------------------------------------------------
    # Physical resources come exclusively from data_mesh.json
    # ------------------------------------------------------------------------

    data_mesh_resources = (
        collect_data_mesh_resources(data_mesh)
    )

    print()
    print(
        f"Data Mesh resources: "
        f"{len(data_mesh_resources)}"
    )

    # ------------------------------------------------------------------------
    # Security groups
    # ------------------------------------------------------------------------

    security_groups = resolver.security_groups()

    print()
    print(
        f"Security groups: "
        f"{len(security_groups)}"
    )

    for security_group in security_groups:
        print(f"  {security_group}")

    # ------------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------------

    known_actions = resolver.collect_allowed_actions()

    executable_actions = []

    print()
    print("EXECUTABLE ACTIONS:")

    for action in sorted(known_actions):

        if build_sql(
            action=action,
            catalog="catalog",
            schema="schema",
            table="table",
        ) is None:
            continue

        executable_actions.append(action)

        print(f"  {action}")

    # ------------------------------------------------------------------------
    # Allowed tests
    # ------------------------------------------------------------------------

    allowed = generate_allowed_tests(
        resolver=resolver,
        data_mesh_resources=data_mesh_resources,
        known_actions=executable_actions,
    )

    print(
        "Generated allowed tests:",
        len(allowed),
    )

    # ------------------------------------------------------------------------
    # Denied tests
    # ------------------------------------------------------------------------

    denied = generate_denied_tests(
        resolver=resolver,
        data_mesh_resources=data_mesh_resources,
        known_actions=executable_actions,
    )

    print(
        "Generated denied tests:",
        len(denied),
    )

    # ------------------------------------------------------------------------
    # Deduplicate
    # ------------------------------------------------------------------------

    allowed, allowed_duplicates = (
        deduplicate_tests(allowed)
    )

    denied, denied_duplicates = (
        deduplicate_tests(denied)
    )

    print()

    print(
        "Removed duplicates:",
        allowed_duplicates + denied_duplicates,
    )

    # ------------------------------------------------------------------------
    # Balance
    # ------------------------------------------------------------------------

    tests = balance_tests(
        allowed=allowed,
        denied=denied,
        max_tests=max_tests,
    )

    # ------------------------------------------------------------------------
    # IDs
    # ------------------------------------------------------------------------

    tests = add_ids(tests)

    # ------------------------------------------------------------------------
    # Output directory
    # ------------------------------------------------------------------------

    GENERATED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    # ------------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------------

    output = {
        "metadata": {
            "generated_at": timestamp,
            "source": str(TREE_PATH),
            "data_mesh_source": str(DATA_MESH_PATH),
            "select_limit": SELECT_LIMIT,
            "max_tests": max_tests,
            "number_of_tests": len(tests),
            "allowed_tests": sum(
                test["expected_allowed"]
                for test in tests
            ),
            "denied_tests": sum(
                not test["expected_allowed"]
                for test in tests
            ),
        },
        "tests": tests,
    }

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            output,
            file,
            indent=4,
        )

    # ------------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------------

    print_generation_statistics(tests)

    print()

    print(
        f"Generated file:\n{OUTPUT_FILE}"
    )

    return output


# ============================================================================
# Standalone
# ============================================================================

if __name__ == "__main__":

    build_permission_tree_from_directory(
        str(OPA_FILE_PATH),
        str(CHECK_FOR_ACTION_PATH),
        str(SECURITY_GROUPS_PATH),
        str(OUTPUT_PATH),
    )

    generate_tests(
        max_tests=MAX_TESTS
    )