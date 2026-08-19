import json
import random
from datetime import datetime
from pathlib import Path


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

GENERATED_DIR = (
    BASE_DIR
    / "generated"
)

OUTPUT_FILE = (
    GENERATED_DIR
    / "trino_tests.json"
)


# ============================================================================
# SQL generation
# ============================================================================

def build_sql(
    action,
    catalog,
    schema,
    table
):
    """
    Convert an action into executable Trino SQL.

    Only actions with a known SQL representation are generated.
    """

    if action == "SelectFromTableAction":

        return (
            f"SELECT * "
            f"FROM {catalog}.{schema}.{table} "
            f"LIMIT {SELECT_LIMIT}"
        )

    if action == "ShowTablesAction":

        return (
            f"SHOW TABLES "
            f"FROM {catalog}.{schema}"
        )

    if action == "ShowSchemasAction":

        return (
            f"SHOW SCHEMAS "
            f"FROM {catalog}"
        )

    return None


# ============================================================================
# Load tree
# ============================================================================

def load_tree():

    if not TREE_PATH.exists():

        raise FileNotFoundError(
            f"tree.json not found:\n{TREE_PATH}"
        )

    with TREE_PATH.open(
        "r",
        encoding="utf-8"
    ) as file:

        tree = json.load(file)

    if not isinstance(tree, dict):

        raise ValueError(
            "tree.json must contain a JSON object"
        )

    return tree


# ============================================================================
# Load Data Mesh
# ============================================================================

def load_data_mesh():

    if not DATA_MESH_PATH.exists():

        raise FileNotFoundError(
            f"data_mesh.json not found:\n{DATA_MESH_PATH}"
        )

    with DATA_MESH_PATH.open(
        "r",
        encoding="utf-8"
    ) as file:

        data_mesh = json.load(file)

    if not isinstance(data_mesh, dict):

        raise ValueError(
            "data_mesh.json must contain a JSON object"
        )

    return data_mesh


# ============================================================================
# Data Mesh resources
# ============================================================================

def collect_data_mesh_resources(
    data_mesh
):
    """
    Return every concrete table defined in data_mesh.json.

    data_mesh.json is the authoritative source for physical resources.
    """

    resources = []

    catalogs = data_mesh.get(
        "catalogs",
        []
    )

    if not isinstance(
        catalogs,
        list
    ):
        return resources

    for catalog_node in catalogs:

        if not isinstance(
            catalog_node,
            dict
        ):
            continue

        catalog = catalog_node.get(
            "name"
        )

        if not catalog:
            continue

        schemas = catalog_node.get(
            "schemas",
            []
        )

        if not isinstance(
            schemas,
            list
        ):
            continue

        for schema_node in schemas:

            if not isinstance(
                schema_node,
                dict
            ):
                continue

            schema = schema_node.get(
                "name"
            )

            if not schema:
                continue

            tables = schema_node.get(
                "tables",
                []
            )

            if not isinstance(
                tables,
                list
            ):
                continue

            for table_node in tables:

                if not isinstance(
                    table_node,
                    dict
                ):
                    continue

                table = table_node.get(
                    "name"
                )

                if not table:
                    continue

                resources.append(
                    {
                        "catalog": catalog,
                        "schema": schema,
                        "table": table
                    }
                )

    return resources


# ============================================================================
# Security groups
# ============================================================================

def collect_security_groups(
    tree
):
    """
    Return every security group defined in tree.json.
    """

    return sorted(
        tree.keys()
    )


# ============================================================================
# Wildcard matching
# ============================================================================

def is_wildcard(
    value
):
    """
    In the generated tree, both None and "*" represent a wildcard.
    """

    return (
        value is None
        or value == "*"
    )


# ============================================================================
# Find catalog node
# ============================================================================

def find_catalog_node(
    group_node,
    catalog
):
    """
    Find the best catalog node.

    Priority:

        1. exact catalog
        2. wildcard catalog

    Wildcard means either None or "*".
    """

    if not isinstance(
        group_node,
        dict
    ):
        return None

    catalogs = group_node.get(
        "catalogs",
        []
    )

    if not isinstance(
        catalogs,
        list
    ):
        return None

    wildcard_node = None

    for node in catalogs:

        if not isinstance(
            node,
            dict
        ):
            continue

        node_catalog = node.get(
            "catalog"
        )

        if node_catalog == catalog:

            return node

        if is_wildcard(
            node_catalog
        ):
            wildcard_node = node

    return wildcard_node


# ============================================================================
# Find schema node
# ============================================================================

def find_schema_node(
    catalog_node,
    schema
):
    """
    Find the best schema node.

    Priority:

        1. exact schema
        2. wildcard schema

    Wildcard means either None or "*".
    """

    if not isinstance(
        catalog_node,
        dict
    ):
        return None

    schemas = catalog_node.get(
        "schemas",
        []
    )

    if not isinstance(
        schemas,
        list
    ):
        return None

    wildcard_node = None

    for node in schemas:

        if not isinstance(
            node,
            dict
        ):
            continue

        node_schema = node.get(
            "schema"
        )

        if node_schema == schema:

            return node

        if is_wildcard(
            node_schema
        ):
            wildcard_node = node

    return wildcard_node


# ============================================================================
# Find table node
# ============================================================================

def find_table_node(
    schema_node,
    table
):
    """
    Find the best table node.

    Priority:

        1. exact table
        2. wildcard table

    Wildcard means either None or "*".
    """

    if not isinstance(
        schema_node,
        dict
    ):
        return None

    tables = schema_node.get(
        "tables",
        []
    )

    if not isinstance(
        tables,
        list
    ):
        return None

    wildcard_node = None

    for node in tables:

        if not isinstance(
            node,
            dict
        ):
            continue

        node_table = node.get(
            "table"
        )

        if node_table == table:

            return node

        if is_wildcard(
            node_table
        ):
            wildcard_node = node

    return wildcard_node


# ============================================================================
# Action helpers
# ============================================================================

def get_action_allowed(
    node
):
    """
    Return the action_allowed dictionary of a tree node.

    Example:

        "action_allowed": {
            "SelectFromTableAction": {
                "requires": [...]
            }
        }
    """

    if not isinstance(
        node,
        dict
    ):
        return {}

    action_allowed = node.get(
        "action_allowed"
    )

    if not isinstance(
        action_allowed,
        dict
    ):
        return {}

    return action_allowed


def is_action_allowed(
    action_allowed,
    action
):
    """
    An action is allowed when it exists in action_allowed.
    """

    if not isinstance(
        action_allowed,
        dict
    ):
        return False

    return action in action_allowed


def get_required_permissions(
    action_data
):
    """
    Extract required permissions from an action.
    """

    if not isinstance(
        action_data,
        dict
    ):
        return []

    requires = action_data.get(
        "requires",
        []
    )

    if not isinstance(
        requires,
        list
    ):
        return []

    return requires


# ============================================================================
# Resolve permissions
# ============================================================================

def resolve_action(
    tree,
    security_group,
    catalog,
    schema,
    table,
    action
):
    """
    Resolve whether an action is allowed for a concrete physical resource.

    Permission precedence:

        1. global_allow_all
        2. exact/wildcard table
        3. schema
        4. catalog
        5. security-group

    New tree structure supports:

        "global_allow_all": true

    When global_allow_all is true, every executable action is allowed
    for every physical resource, unless a more specific restriction is
    explicitly represented in the tree.

    Returns:

        {
            "allowed": True/False,
            "source": "...",
            "action_data": {...} / None
        }
    """

    group_node = tree.get(
        security_group
    )

    if not isinstance(
        group_node,
        dict
    ):
        return {
            "allowed": False,
            "source": None,
            "action_data": None
        }

    # ========================================================================
    # GLOBAL ALLOW ALL
    # ========================================================================

    if group_node.get(
        "global_allow_all",
        False
    ) is True:

        group_actions = get_action_allowed(
            group_node
        )

        if action in group_actions:

            return {
                "allowed": True,
                "source": "global",
                "action_data": group_actions[action]
            }

        # If global_allow_all is true but this action is not present in
        # action_allowed, do not invent permission information.
        return {
            "allowed": False,
            "source": "global",
            "action_data": None
        }

    # ========================================================================
    # NORMAL RESOURCE-BASED RESOLUTION
    # ========================================================================

    catalog_node = find_catalog_node(
        group_node,
        catalog
    )

    # ------------------------------------------------------------------------
    # No catalog node
    # ------------------------------------------------------------------------

    if catalog_node is None:

        group_actions = get_action_allowed(
            group_node
        )

        if action in group_actions:

            return {
                "allowed": True,
                "source": "group",
                "action_data": group_actions[action]
            }

        return {
            "allowed": False,
            "source": None,
            "action_data": None
        }

    # ------------------------------------------------------------------------
    # Catalog level
    # ------------------------------------------------------------------------

    catalog_actions = get_action_allowed(
        catalog_node
    )

    catalog_match = (
        action in catalog_actions
    )

    # ------------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------------

    schema_node = find_schema_node(
        catalog_node,
        schema
    )

    if schema_node is None:

        if catalog_match:

            return {
                "allowed": True,
                "source": "catalog",
                "action_data": catalog_actions[action]
            }

        group_actions = get_action_allowed(
            group_node
        )

        if action in group_actions:

            return {
                "allowed": True,
                "source": "group",
                "action_data": group_actions[action]
            }

        return {
            "allowed": False,
            "source": None,
            "action_data": None
        }

    # ------------------------------------------------------------------------
    # Schema level
    # ------------------------------------------------------------------------

    schema_actions = get_action_allowed(
        schema_node
    )

    schema_match = (
        action in schema_actions
    )

    # ------------------------------------------------------------------------
    # Table
    # ------------------------------------------------------------------------

    table_node = find_table_node(
        schema_node,
        table
    )

    if table_node is not None:

        table_actions = get_action_allowed(
            table_node
        )

        if action in table_actions:

            return {
                "allowed": True,
                "source": "table",
                "action_data": table_actions[action]
            }

        table_action_allowed = table_node.get(
            "action_allowed"
        )

        if table_action_allowed is None:

            if schema_match:

                return {
                    "allowed": True,
                    "source": "schema",
                    "action_data": schema_actions[action]
                }

            if catalog_match:

                return {
                    "allowed": True,
                    "source": "catalog",
                    "action_data": catalog_actions[action]
                }

        elif isinstance(
            table_action_allowed,
            dict
        ):

            return {
                "allowed": False,
                "source": "table",
                "action_data": None
            }

    # ------------------------------------------------------------------------
    # Schema fallback
    # ------------------------------------------------------------------------

    if schema_match:

        return {
            "allowed": True,
            "source": "schema",
            "action_data": schema_actions[action]
        }

    # ------------------------------------------------------------------------
    # Catalog fallback
    # ------------------------------------------------------------------------

    if catalog_match:

        return {
            "allowed": True,
            "source": "catalog",
            "action_data": catalog_actions[action]
        }

    # ------------------------------------------------------------------------
    # Group fallback
    # ------------------------------------------------------------------------

    group_actions = get_action_allowed(
        group_node
    )

    if action in group_actions:

        return {
            "allowed": True,
            "source": "group",
            "action_data": group_actions[action]
        }

    return {
        "allowed": False,
        "source": None,
        "action_data": None
    }


# ============================================================================
# Tree traversal
# ============================================================================

def iter_resources(
    tree
):
    """
    Yield every concrete table explicitly represented in tree.json.

    Wildcards are ignored for discovery.

    The tree is NOT authoritative for physical resources.
    data_mesh.json is authoritative for that.
    """

    for security_group, group_node in tree.items():

        if not isinstance(
            group_node,
            dict
        ):
            continue

        catalogs = group_node.get(
            "catalogs",
            []
        )

        if not isinstance(
            catalogs,
            list
        ):
            continue

        for catalog_node in catalogs:

            if not isinstance(
                catalog_node,
                dict
            ):
                continue

            catalog = catalog_node.get(
                "catalog"
            )

            if is_wildcard(
                catalog
            ):
                continue

            schemas = catalog_node.get(
                "schemas",
                []
            )

            if not isinstance(
                schemas,
                list
            ):
                continue

            for schema_node in schemas:

                if not isinstance(
                    schema_node,
                    dict
                ):
                    continue

                schema = schema_node.get(
                    "schema"
                )

                if is_wildcard(
                    schema
                ):
                    continue

                tables = schema_node.get(
                    "tables",
                    []
                )

                if not isinstance(
                    tables,
                    list
                ):
                    continue

                for table_node in tables:

                    if not isinstance(
                        table_node,
                        dict
                    ):
                        continue

                    table = table_node.get(
                        "table"
                    )

                    if is_wildcard(
                        table
                    ):
                        continue

                    yield (
                        security_group,
                        catalog,
                        schema,
                        table,
                        table_node
                    )


# ============================================================================
# Collect tree resources
# ============================================================================

def collect_resources(
    tree
):

    resources = []

    for (
        security_group,
        catalog,
        schema,
        table,
        table_node
    ) in iter_resources(
        tree
    ):

        resources.append(
            {
                "security_group":
                    security_group,

                "catalog":
                    catalog,

                "schema":
                    schema,

                "table":
                    table,

                "table_node":
                    table_node
            }
        )

    return resources


# ============================================================================
# Collect executable actions
# ============================================================================

def collect_executable_actions(
    tree,
    resources
):
    """
    Collect every executable action appearing anywhere in tree.json.

    IMPORTANT:

    We inspect action_allowed on every node, not only concrete
    table nodes, because permissions may be defined at schema,
    catalog, or group level.
    """

    actions = {}

    def register_actions(
        node
    ):

        action_allowed = get_action_allowed(
            node
        )

        for action, action_data in action_allowed.items():

            if build_sql(
                action=action,
                catalog="catalog",
                schema="schema",
                table="table"
            ) is None:

                continue

            if action not in actions:

                actions[action] = {
                    "required_permissions":
                        get_required_permissions(
                            action_data
                        )
                }

    # ------------------------------------------------------------------------
    # Inspect every node in the tree.
    # ------------------------------------------------------------------------

    for security_group, group_node in tree.items():

        if not isinstance(
            group_node,
            dict
        ):
            continue

        register_actions(
            group_node
        )

        catalogs = group_node.get(
            "catalogs",
            []
        )

        if not isinstance(
            catalogs,
            list
        ):
            continue

        for catalog_node in catalogs:

            if not isinstance(
                catalog_node,
                dict
            ):
                continue

            register_actions(
                catalog_node
            )

            schemas = catalog_node.get(
                "schemas",
                []
            )

            if not isinstance(
                schemas,
                list
            ):
                continue

            for schema_node in schemas:

                if not isinstance(
                    schema_node,
                    dict
                ):
                    continue

                register_actions(
                    schema_node
                )

                tables = schema_node.get(
                    "tables",
                    []
                )

                if not isinstance(
                    tables,
                    list
                ):
                    continue

                for table_node in tables:

                    if not isinstance(
                        table_node,
                        dict
                    ):
                        continue

                    register_actions(
                        table_node
                    )

    return actions


# ============================================================================
# Allowed tests
# ============================================================================

def generate_allowed_tests(
    tree,
    resources,
    data_mesh_resources
):

    tests = []

    security_groups = collect_security_groups(tree)

    known_actions = collect_executable_actions(
        tree,
        resources
    )

    for mesh_resource in data_mesh_resources:

        catalog = mesh_resource["catalog"]
        schema = mesh_resource["schema"]
        table = mesh_resource["table"]

        for security_group in security_groups:

            for action in known_actions:

                result = resolve_action(
                    tree=tree,
                    security_group=security_group,
                    catalog=catalog,
                    schema=schema,
                    table=table,
                    action=action
                )

                if not result["allowed"]:
                    continue

                sql = build_sql(
                    action=action,
                    catalog=catalog,
                    schema=schema,
                    table=table
                )

                if sql is None:
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
                        "required_permissions": get_required_permissions(
                            result["action_data"]
                        ),
                        "permission_source": result["source"],
                        "test_type": "allowed"
                    }
                )

    return tests


# ============================================================================
# Denied tests
# ============================================================================

def generate_denied_tests(
    tree,
    resources,
    data_mesh_resources
):

    tests = []

    security_groups = collect_security_groups(tree)

    known_actions = collect_executable_actions(
        tree,
        resources
    )

    for mesh_resource in data_mesh_resources:

        catalog = mesh_resource["catalog"]
        schema = mesh_resource["schema"]
        table = mesh_resource["table"]

        for security_group in security_groups:

            for action, action_info in known_actions.items():

                result = resolve_action(
                    tree=tree,
                    security_group=security_group,
                    catalog=catalog,
                    schema=schema,
                    table=table,
                    action=action
                )

                if result["allowed"]:
                    continue

                sql = build_sql(
                    action=action,
                    catalog=catalog,
                    schema=schema,
                    table=table
                )

                if sql is None:
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
                        "required_permissions": action_info[
                            "required_permissions"
                        ],
                        "permission_source": result["source"],
                        "test_type": "denied"
                    }
                )

    return tests

# ============================================================================
# Deduplication
# ============================================================================

def deduplicate_tests(
    tests
):

    unique = {}

    duplicates = 0

    for test in tests:

        key = (
            test["security_group"],
            test["action"],
            test["catalog"],
            test["schema"],
            test["table"],
            test["expected_allowed"]
        )

        if key in unique:

            duplicates += 1

            continue

        unique[key] = test

    return (
        list(unique.values()),
        duplicates
    )


# ============================================================================
# Balance
# ============================================================================

def balance_tests(
    allowed,
    denied,
    max_tests=None
):

    random.seed(
        RANDOM_SEED
    )

    random.shuffle(
        allowed
    )

    random.shuffle(
        denied
    )

    if max_tests is None:

        result = (
            allowed
            + denied
        )

        random.shuffle(
            result
        )

        return result

    # ------------------------------------------------------------------------
    # If one side does not contain enough tests, use the available tests
    # and fill the remaining slots from the other side.
    # ------------------------------------------------------------------------

    target_allowed = int(
        max_tests
        * TARGET_ALLOWED_RATIO
    )

    target_denied = (
        max_tests
        - target_allowed
    )

    selected_allowed = allowed[
        :target_allowed
    ]

    selected_denied = denied[
        :target_denied
    ]

    result = (
        selected_allowed
        + selected_denied
    )

    # Fill remaining slots if one category was too small.
    if len(result) < max_tests:

        remaining_allowed = allowed[
            len(selected_allowed):
        ]

        remaining_denied = denied[
            len(selected_denied):
        ]

        remaining = (
            remaining_allowed
            + remaining_denied
        )

        random.shuffle(
            remaining
        )

        needed = (
            max_tests
            - len(result)
        )

        result.extend(
            remaining[:needed]
        )

    random.shuffle(
        result
    )

    return result


# ============================================================================
# IDs
# ============================================================================

def add_ids(
    tests
):

    for index, test in enumerate(
        tests,
        start=1
    ):

        test["id"] = (
            f"test_{index:06d}"
        )

    return tests


# ============================================================================
# Statistics
# ============================================================================

def print_generation_statistics(
    tests
):

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
            test["table"]
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
        test.get(
            "permission_source"
        )
        for test in tests
    }

    print()
    print("=" * 70)
    print(" GENERATED TEST STATISTICS")
    print("=" * 70)

    print(
        f"Total tests:       {len(tests)}"
    )

    print(
        f"Allowed:           {allowed}"
    )

    print(
        f"Denied:            {denied}"
    )

    print(
        f"Security groups:   {len(security_groups)}"
    )

    print(
        f"Resources:         {len(resources)}"
    )

    print(
        f"Actions:            {len(actions)}"
    )

    print()

    print(
        "Actions:"
    )

    for action in sorted(
        actions
    ):

        count = sum(
            test["action"] == action
            for test in tests
        )

        print(
            f"  {action}: {count}"
        )

    print()

    print(
        "Security groups:"
    )

    for group in sorted(
        security_groups
    ):

        count = sum(
            test["security_group"] == group
            for test in tests
        )

        print(
            f"  {group}: {count}"
        )

    print()

    print(
        "Resources:"
    )

    for (
        catalog,
        schema,
        table
    ) in sorted(
        resources
    ):

        count = sum(
            test["catalog"] == catalog
            and test["schema"] == schema
            and test["table"] == table
            for test in tests
        )

        print(
            f"  {catalog}.{schema}.{table}: "
            f"{count}"
        )

    print()

    print(
        "Permission sources:"
    )

    for source in sorted(
        str(source)
        for source in permission_sources
    ):

        count = sum(
            str(
                test.get(
                    "permission_source"
                )
            ) == source
            for test in tests
        )

        print(
            f"  {source}: {count}"
        )

    print()

    print(
        "Test types:"
    )

    for test_type in sorted(
        test_types
    ):

        count = sum(
            test["test_type"] == test_type
            for test in tests
        )

        print(
            f"  {test_type}: {count}"
        )


# ============================================================================
# Main generation function
# ============================================================================

def generate_tests(
    max_tests=MAX_TESTS
):

    print("=" * 70)
    print(" TRINO PERFORMANCE TEST GENERATOR")
    print("=" * 70)

    print(
        f"Tree:\n{TREE_PATH}"
    )

    print(
        f"Data Mesh:\n{DATA_MESH_PATH}"
    )

    # ========================================================================
    # Load
    # ========================================================================

    tree = load_tree()

    data_mesh = load_data_mesh()

    # ========================================================================
    # Inspect
    # ========================================================================

    inspect_tree(
        tree
    )

    # ========================================================================
    # Tree resources
    # ========================================================================

    resources = collect_resources(
        tree
    )

    # ========================================================================
    # Data Mesh resources
    # ========================================================================

    data_mesh_resources = (
        collect_data_mesh_resources(
            data_mesh
        )
    )

    print()
    print(
        f"Tree resources: "
        f"{len(resources)}"
    )

    print(
        f"Data Mesh resources: "
        f"{len(data_mesh_resources)}"
    )

    print()

    print(
        "DATA MESH TABLES:"
    )

    for resource in data_mesh_resources:

        print(
            f"  "
            f"{resource['catalog']}."
            f"{resource['schema']}."
            f"{resource['table']}"
        )

    # ========================================================================
    # Security groups
    # ========================================================================

    security_groups = (
        collect_security_groups(
            tree
        )
    )

    print()

    print(
        f"Security groups: "
        f"{len(security_groups)}"
    )

    for security_group in security_groups:

        print(
            f"  {security_group}"
        )

    # ========================================================================
    # Concrete resources represented in tree
    # ========================================================================

    physical_resources = {
        (
            resource["catalog"],
            resource["schema"],
            resource["table"]
        )
        for resource in resources
    }

    print()

    print(
        f"Concrete tree resources: "
        f"{len(physical_resources)}"
    )

    # ========================================================================
    # Known actions
    # ========================================================================

    known_actions = collect_executable_actions(
        tree,
        resources
    )

    print()

    print(
        "EXECUTABLE ACTIONS:"
    )

    for action in sorted(
        known_actions
    ):

        print(
            f"  {action}"
        )

    # ========================================================================
    # Allowed
    # ========================================================================

    allowed = generate_allowed_tests(
        tree=tree,
        resources=resources,
        data_mesh_resources=data_mesh_resources
    )

    print()

    print(
        f"Allowed candidates: "
        f"{len(allowed)}"
    )

    # ========================================================================
    # Denied
    # ========================================================================

    denied = generate_denied_tests(
        tree=tree,
        resources=resources,
        data_mesh_resources=data_mesh_resources
    )

    print(
        f"Denied candidates: "
        f"{len(denied)}"
    )

    # ========================================================================
    # Deduplicate
    # ========================================================================

    allowed, allowed_duplicates = (
        deduplicate_tests(
            allowed
        )
    )

    denied, denied_duplicates = (
        deduplicate_tests(
            denied
        )
    )

    print()

    print(
        f"Removed duplicates: "
        f"{allowed_duplicates + denied_duplicates}"
    )

    # ========================================================================
    # Balance
    # ========================================================================

    tests = balance_tests(
        allowed=allowed,
        denied=denied,
        max_tests=max_tests
    )

    # ========================================================================
    # IDs
    # ========================================================================

    tests = add_ids(
        tests
    )

    # ========================================================================
    # Output directory
    # ========================================================================

    GENERATED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    # ========================================================================
    # Output
    # ========================================================================

    output = {
        "metadata": {
            "generated_at":
                timestamp,

            "source":
                str(TREE_PATH),

            "data_mesh_source":
                str(DATA_MESH_PATH),

            "select_limit":
                SELECT_LIMIT,

            "max_tests":
                max_tests,

            "number_of_tests":
                len(tests),

            "allowed_tests":
                sum(
                    test["expected_allowed"]
                    for test in tests
                ),

            "denied_tests":
                sum(
                    not test["expected_allowed"]
                    for test in tests
                )
        },

        "tests":
            tests
    }

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=4
        )

    # ========================================================================
    # Statistics
    # ========================================================================

    print_generation_statistics(
        tests
    )

    print()

    print(
        f"Generated file:\n{OUTPUT_FILE}"
    )

    return output


# ============================================================================
# Tree inspection
# ============================================================================

def inspect_tree(
    tree
):

    print()
    print("=" * 70)
    print(" TREE STRUCTURE")
    print("=" * 70)

    for security_group, group_node in tree.items():

        print(
            f"\nSECURITY GROUP: {security_group}"
        )

        if not isinstance(
            group_node,
            dict
        ):
            print(
                f"  Unexpected node: "
                f"{type(group_node)}"
            )
            continue

        print(
            "  keys:",
            list(group_node.keys())
        )

        group_actions = get_action_allowed(
            group_node
        )

        if group_actions:

            print(
                "  group action_allowed:",
                json.dumps(
                    group_actions,
                    indent=4
                )
            )

        catalogs = group_node.get(
            "catalogs",
            []
        )

        if not isinstance(
            catalogs,
            list
        ):
            continue

        for catalog_node in catalogs:

            if not isinstance(
                catalog_node,
                dict
            ):
                continue

            print(
                f"  CATALOG: "
                f"{catalog_node.get('catalog')}"
            )

            print(
                "    keys:",
                list(catalog_node.keys())
            )

            catalog_actions = get_action_allowed(
                catalog_node
            )

            if catalog_actions:

                print(
                    "    catalog action_allowed:",
                    json.dumps(
                        catalog_actions,
                        indent=4
                    )
                )

            schemas = catalog_node.get(
                "schemas",
                []
            )

            if not isinstance(
                schemas,
                list
            ):
                continue

            for schema_node in schemas:

                if not isinstance(
                    schema_node,
                    dict
                ):
                    continue

                print(
                    f"    SCHEMA: "
                    f"{schema_node.get('schema')}"
                )

                print(
                    "      keys:",
                    list(schema_node.keys())
                )

                schema_actions = get_action_allowed(
                    schema_node
                )

                if schema_actions:

                    print(
                        "      schema action_allowed:",
                        json.dumps(
                            schema_actions,
                            indent=4
                        )
                    )

                tables = schema_node.get(
                    "tables",
                    []
                )

                if not isinstance(
                    tables,
                    list
                ):
                    continue

                for table_node in tables:

                    if not isinstance(
                        table_node,
                        dict
                    ):
                        continue

                    print(
                        f"      TABLE: "
                        f"{table_node.get('table')}"
                    )

                    print(
                        "        keys:",
                        list(table_node.keys())
                    )

                    print(
                        "        action_allowed:",
                        json.dumps(
                            table_node.get(
                                "action_allowed"
                            ),
                            indent=4
                        )
                    )


# ============================================================================
# Standalone
# ============================================================================

import os
from dotenv import load_dotenv
from openai import OpenAI

from TreePermission.tree_builder import build_permission_tree_from_directory

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
from pathlib import Path

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

OUTPUT_PATH = os.path.join(os.path.join(os.path.join(os.path.join(DATA_MESH_DIR,"StatefulRuleArchitecture" ), "trino_permission"), "tree_permission"), "tree.json")





if __name__ == "__main__":
    build_permission_tree_from_directory(OPA_FILE_PATH, CHECK_FOR_ACTION_PATH, SECURITY_GROUPS_PATH, OUTPUT_PATH)

    generate_tests(
        max_tests=MAX_TESTS
    )