import json
import os
import copy
import tempfile

from TreePermission.TreeBuilder import build_permission_tree

from Function.LoadJson import load_json


def _find_node(nodes, key, value):
    """
    Find a node in a list by its identifying key.
    """
    if not nodes:
        return None

    for node in nodes:
        if node.get(key) == value:
            return node

    return None

def get_new_permission_tree(
    new_tree_file,
    tree_directory
):
    """
    Compare a newly generated permission tree against all
    previously generated/installed permission trees.

    Returns only permissions introduced by the new policy.
    """

    with open(
        new_tree_file,
        "r",
        encoding="utf-8"
    ) as f:

        new_tree = json.load(f)

    existing_tree = load_existing_permission_trees(
        tree_directory,
        exclude_file=new_tree_file
    )

    difference = subtract_permission_tree(
        new_tree,
        existing_tree
    )

    return difference

def merge_filters(
    target,
    source
):
    if not target:
        return copy.deepcopy(source)

    if not source:
        return target

    result = copy.deepcopy(target)

    for filter_name, values in source.items():

        result[filter_name] = _merge_list(
            result.get(filter_name, []),
            values or []
        )

    return result

def merge_actions(
    target,
    source
):
    if not target:
        return copy.deepcopy(source)

    if not source:
        return target

    result = copy.deepcopy(target)

    for action_name, action_value in source.items():

        if action_name not in result:
            result[action_name] = copy.deepcopy(
                action_value
            )

    return result

def merge_nodes(
    target_nodes,
    source_nodes,
    node_key,
    children_key
):
    for source_node in source_nodes:

        source_value = source_node.get(
            node_key
        )

        target_node = _find_node(
            target_nodes,
            node_key,
            source_value
        )

        # Completely new node
        if target_node is None:
            target_nodes.append(
                copy.deepcopy(source_node)
            )
            continue

        # Permissions
        target_node["permission"] = _merge_list(
            target_node.get("permission") or [],
            source_node.get("permission") or []
        )

        # Filters
        target_node["filters"] = merge_filters(
            target_node.get("filters"),
            source_node.get("filters")
        )

        # Actions
        target_node["action_allowed"] = merge_actions(
            target_node.get("action_allowed"),
            source_node.get("action_allowed")
        )

        # Children
        source_children = source_node.get(
            children_key,
            []
        )

        if not source_children:
            continue

        if children_key == "schemas":
            next_key = "schema"
            next_children = "tables"

        elif children_key == "tables":
            next_key = "table"
            next_children = "columns"

        elif children_key == "columns":
            next_key = "column"
            next_children = None

        else:
            next_key = None
            next_children = None

        if next_key is not None:

            merge_nodes(
                target_node.setdefault(
                    children_key,
                    []
                ),
                source_children,
                next_key,
                next_children
            )

def _merge_list(a, b):
    result = copy.deepcopy(a)

    existing = {
        json.dumps(
            _normalize(item),
            sort_keys=True,
            ensure_ascii=False
        )
        for item in result
    }

    for item in b:

        key = json.dumps(
            _normalize(item),
            sort_keys=True,
            ensure_ascii=False
        )

        if key not in existing:
            result.append(
                copy.deepcopy(item)
            )
            existing.add(key)

    return result


def merge_permission_tree(
    target,
    source
):
    """
    Merge source permission tree into target.

    This is used to build the representation of all permissions
    already installed in OPA.
    """

    for group_name, source_group in source.items():

        if group_name not in target:
            target[group_name] = copy.deepcopy(
                source_group
            )
            continue

        target_group = target[group_name]

        # ---------------------------------------------------------
        # PERMISSIONS
        # ---------------------------------------------------------

        target_group["permission"] = _merge_list(
            target_group.get("permission") or [],
            source_group.get("permission") or []
        )

        # ---------------------------------------------------------
        # FILTERS
        # ---------------------------------------------------------

        target_group["filters"] = merge_filters(
            target_group.get("filters"),
            source_group.get("filters")
        )

        # ---------------------------------------------------------
        # ACTIONS
        # ---------------------------------------------------------

        target_group["action_allowed"] = merge_actions(
            target_group.get("action_allowed"),
            source_group.get("action_allowed")
        )

        # ---------------------------------------------------------
        # CATALOGS
        # ---------------------------------------------------------

        merge_nodes(
            target_group.setdefault(
                "catalogs",
                []
            ),
            source_group.get(
                "catalogs",
                []
            ),
            "catalog",
            "schemas"
        )

def load_existing_permission_trees(
    tree_directory,
    exclude_file=None
):
    """
    Load and merge all existing permission-tree JSON files.
    """

    merged = {}

    if not os.path.exists(tree_directory):
        return merged

    for filename in os.listdir(tree_directory):

        if not filename.endswith(".json"):
            continue

        filepath = os.path.join(
            tree_directory,
            filename
        )

        if exclude_file is not None:
            if os.path.abspath(filepath) == os.path.abspath(exclude_file):
                continue

        try:

            with open(
                filepath,
                "r",
                encoding="utf-8"
            ) as f:

                tree = json.load(f)

        except Exception as e:

            print(
                f"Failed to read permission tree "
                f"{filepath}: {e}"
            )

            continue

        merge_permission_tree(
            merged,
            tree
        )

    return merged

def _normalize(value):
    """
    Normalize JSON values so they can be compared reliably.
    """
    if isinstance(value, dict):
        return {
            key: _normalize(value[key])
            for key in sorted(value)
        }

    if isinstance(value, list):
        normalized = [_normalize(v) for v in value]

        # Lists in permission trees are generally unordered.
        return sorted(
            normalized,
            key=lambda x: json.dumps(
                x,
                sort_keys=True,
                ensure_ascii=False
            )
        )

    return value


def _json_equal(a, b):
    return _normalize(a) == _normalize(b)


def _subtract_list(new_list, old_list):
    """
    Return elements present in new_list but not in old_list.
    """
    if not new_list:
        return []

    old_normalized = {
        json.dumps(
            _normalize(item),
            sort_keys=True,
            ensure_ascii=False
        )
        for item in old_list
    }

    result = []

    for item in new_list:
        key = json.dumps(
            _normalize(item),
            sort_keys=True,
            ensure_ascii=False
        )

        if key not in old_normalized:
            result.append(copy.deepcopy(item))

    return result

def subtract_filters(
    new_filters,
    old_filters
):
    """
    Return only filters that are not already present.

    Example:

    new:
    {
        "GetColumnMask": [
            {"expression": "'REDACTED'"}
        ]
    }

    old:
    {
        "GetColumnMask": [
            {"expression": "'REDACTED'"}
        ]
    }

    result:
    None
    """

    if not new_filters:
        return None

    if not old_filters:
        return copy.deepcopy(new_filters)

    result = {}

    for filter_name, new_values in new_filters.items():

        old_values = old_filters.get(
            filter_name,
            []
        )

        difference = _subtract_list(
            new_values or [],
            old_values or []
        )

        if difference:
            result[filter_name] = difference

    return result if result else None


def subtract_action_allowed(
    new_actions,
    old_actions
):
    """
    Return only actions that are not already present.

    If an action exists in the old tree, it is considered already
    represented and is therefore removed from the new tree.
    """

    if not new_actions:
        return None

    if not old_actions:
        return copy.deepcopy(new_actions)

    result = {}

    for action_name, action_value in new_actions.items():

        old_action = old_actions.get(action_name)

        if old_action is None:
            result[action_name] = copy.deepcopy(action_value)
            continue

        # Same action already exists.
        # Do not duplicate it.
        if not _json_equal(
            action_value,
            old_action
        ):
            # If the definition changed, keep the new one.
            result[action_name] = copy.deepcopy(action_value)

    return result if result else None

def subtract_nodes(
    new_nodes,
    old_nodes,
    node_key,
    children_key
):
    """
    Recursively subtract hierarchical permission nodes.

    Example:

        catalogs
            catalog
                schemas
                    schema
                        tables
                            table
                                columns
                                    column
    """

    if not new_nodes:
        return []

    result = []

    for new_node in new_nodes:

        node_value = new_node.get(node_key)

        old_node = _find_node(
            old_nodes,
            node_key,
            node_value
        )

        # Entirely new node
        if old_node is None:
            result.append(
                copy.deepcopy(new_node)
            )
            continue

        diff_node = {}

        # ---------------------------------------------------------
        # NODE PERMISSIONS
        # ---------------------------------------------------------

        new_permissions = (
            new_node.get("permission") or []
        )

        old_permissions = (
            old_node.get("permission") or []
        )

        permission_diff = _subtract_list(
            new_permissions,
            old_permissions
        )

        if permission_diff:
            diff_node["permission"] = permission_diff

        # ---------------------------------------------------------
        # NODE FILTERS
        # ---------------------------------------------------------

        filter_diff = subtract_filters(
            new_node.get("filters"),
            old_node.get("filters")
        )

        if filter_diff is not None:
            diff_node["filters"] = filter_diff

        # ---------------------------------------------------------
        # ACTIONS
        # ---------------------------------------------------------

        action_diff = subtract_action_allowed(
            new_node.get("action_allowed"),
            old_node.get("action_allowed")
        )

        if action_diff:
            diff_node["action_allowed"] = action_diff

        # ---------------------------------------------------------
        # CHILDREN
        # ---------------------------------------------------------

        children = new_node.get(
            children_key,
            []
        )

        if children:

            if children_key == "catalogs":
                child_key = "catalog"
                next_children_key = "schemas"

            elif children_key == "schemas":
                child_key = "schema"
                next_children_key = "tables"

            elif children_key == "tables":
                child_key = "table"
                next_children_key = "columns"

            elif children_key == "columns":
                child_key = "column"
                next_children_key = None

            else:
                child_key = None
                next_children_key = None

            if next_children_key is not None:

                child_diff = subtract_nodes(
                    children,
                    old_node.get(children_key, []),
                    child_key,
                    next_children_key
                )

                if child_diff:
                    diff_node[children_key] = child_diff

            else:
                # columns have no further children
                old_children = old_node.get(
                    children_key,
                    []
                )

                column_diff = []

                for new_column in children:

                    column_name = new_column.get(
                        "column"
                    )

                    old_column = _find_node(
                        old_children,
                        "column",
                        column_name
                    )

                    if old_column is None:
                        column_diff.append(
                            copy.deepcopy(new_column)
                        )
                        continue

                    column_result = {}

                    permission_diff = _subtract_list(
                        new_column.get("permission") or [],
                        old_column.get("permission") or []
                    )

                    if permission_diff:
                        column_result["permission"] = permission_diff

                    filter_diff = subtract_filters(
                        new_column.get("filters"),
                        old_column.get("filters")
                    )

                    if filter_diff is not None:
                        column_result["filters"] = filter_diff

                    action_diff = subtract_action_allowed(
                        new_column.get("action_allowed"),
                        old_column.get("action_allowed")
                    )

                    if action_diff:
                        column_result["action_allowed"] = action_diff

                    if column_result:
                        column_result["column"] = column_name
                        column_diff.append(
                            column_result
                        )

                if column_diff:
                    diff_node[children_key] = column_diff

        if diff_node:
            # Always retain identity of the node.
            diff_node[node_key] = node_value

            # Keep identity first for readability.
            ordered_node = {
                node_key: diff_node.pop(node_key),
                **diff_node
            }

            result.append(
                ordered_node
            )

    return result



def subtract_permission_tree(
    new_tree,
    existing_tree
):
    """
    Return only the permissions/filters/actions that exist in
    new_tree but are not already present in existing_tree.
    """

    result = {}

    for group_name, new_group in new_tree.items():

        old_group = existing_tree.get(group_name)

        # Completely new group
        if old_group is None:
            result[group_name] = copy.deepcopy(new_group)
            continue

        diff_group = {}

        # ---------------------------------------------------------
        # GROUP PERMISSIONS
        # ---------------------------------------------------------

        new_permissions = new_group.get("permission") or []
        old_permissions = old_group.get("permission") or []

        permission_diff = _subtract_list(
            new_permissions,
            old_permissions
        )

        if permission_diff:
            diff_group["permission"] = permission_diff

        # ---------------------------------------------------------
        # GROUP FILTERS
        # ---------------------------------------------------------

        new_filters = new_group.get("filters")
        old_filters = old_group.get("filters")

        filter_diff = subtract_filters(
            new_filters,
            old_filters
        )

        if filter_diff is not None:
            diff_group["filters"] = filter_diff

        # ---------------------------------------------------------
        # GROUP ACTIONS
        # ---------------------------------------------------------

        action_diff = subtract_action_allowed(
            new_group.get("action_allowed"),
            old_group.get("action_allowed")
        )

        if action_diff:
            diff_group["action_allowed"] = action_diff

        # ---------------------------------------------------------
        # CATALOGS
        # ---------------------------------------------------------

        catalog_diff = subtract_nodes(
            new_group.get("catalogs", []),
            old_group.get("catalogs", []),
            "catalog",
            "catalogs"
        )

        if catalog_diff:
            diff_group["catalogs"] = catalog_diff

        # ---------------------------------------------------------
        # ONLY KEEP GROUP IF SOMETHING WAS ADDED
        # ---------------------------------------------------------

        if diff_group:
            result[group_name] = diff_group

    return result



def build_complete_permission_tree(tree_permission_dir, tree_structure_path, output_rego_dir, check_for_action_path,security_groups_path):
    """
    Build the cumulative permission tree from all accepted
    Rego policies currently present in output_rego_dir.

    The result is saved as:

        tree_permission/tree_structure.json
    """

    os.makedirs(
        tree_permission_dir,
        exist_ok=True
    )

    rego_files = [
        os.path.join(
            output_rego_dir,
            filename
        )
        for filename in os.listdir(output_rego_dir)
        if filename.endswith(".rego")
    ]

    if not rego_files:
        return {}

    # ---------------------------------------------------------
    # Temporary combined Rego
    # ---------------------------------------------------------

    temporary_rego = os.path.join(
        tree_permission_dir,
        "_combined_policies.rego"
    )

    with open(
        temporary_rego,
        "w",
        encoding="utf-8"
    ) as output:

        for rego_file in sorted(rego_files):

            with open(
                rego_file,
                "r",
                encoding="utf-8"
            ) as source:

                output.write(
                    source.read()
                )

                output.write(
                    "\n\n"
                )

    # ---------------------------------------------------------
    # Build cumulative tree
    # ---------------------------------------------------------

    temporary_tree = os.path.join(
        tree_permission_dir,
        "_combined_tree.json"
    )

    try:

        build_permission_tree(
            opa_file=temporary_rego,
            action_permissions_file=check_for_action_path,
            security_groups_file=security_groups_path,
            output_file=temporary_tree
        )

        complete_tree = load_json(
            temporary_tree
        )

    finally:

        if os.path.exists(
            temporary_rego
        ):
            os.remove(
                temporary_rego
            )

        if os.path.exists(
            temporary_tree
        ):
            os.remove(
                temporary_tree
            )

    # ---------------------------------------------------------
    # Save cumulative structure
    # ---------------------------------------------------------

    with open(
        tree_structure_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            complete_tree,
            f,
            indent=2,
            ensure_ascii=False
        )

    return complete_tree


def get_permission_difference(
    candidate_tree_file,
    tree_permission_dir,
    tree_structure_path
):
    """
    Compare the candidate tree against the current cumulative
    tree_structure.json.

    get_new_permission_tree() expects a directory containing
    previous trees, therefore we create a temporary directory
    containing only the current cumulative tree.
    """

    comparison_dir = os.path.join(
        tree_permission_dir,
        "_comparison"
    )

    os.makedirs(
        comparison_dir,
        exist_ok=True
    )

    try:

        # -----------------------------------------------------
        # No previous tree
        # -----------------------------------------------------

        if not os.path.exists(
            tree_structure_path
        ):

            return load_json(
                candidate_tree_file
            )

        # -----------------------------------------------------
        # Put current cumulative tree into comparison dir
        # -----------------------------------------------------

        existing_tree_file = os.path.join(
            comparison_dir,
            "tree_structure.json"
        )

        with open(
            tree_structure_path,
            "r",
            encoding="utf-8"
        ) as source:

            existing_tree = json.load(
                source
            )

        with open(
            existing_tree_file,
            "w",
            encoding="utf-8"
        ) as destination:

            json.dump(
                existing_tree,
                destination,
                indent=2,
                ensure_ascii=False
            )

        # -----------------------------------------------------
        # Compare candidate with cumulative tree
        # -----------------------------------------------------

        difference = get_new_permission_tree(
            new_tree_file=candidate_tree_file,
            tree_directory=comparison_dir
        )

        return difference

    finally:

        if os.path.exists(
            comparison_dir
        ):

            for filename in os.listdir(
                comparison_dir
            ):

                file_path = os.path.join(
                    comparison_dir,
                    filename
                )

                if os.path.isfile(
                    file_path
                ):
                    os.remove(
                        file_path
                    )

            os.rmdir(
                comparison_dir
            )