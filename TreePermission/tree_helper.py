import json
import os
import copy

from TreePermission.tree_builder import build_permission_tree_from_directory
from Function.LoadJson import load_json

# ============================================================================
# Basic helpers
# ============================================================================

def _find_node(nodes, key, value):
    """Find a node in a list by its identifying key."""
    if not nodes:
        return None

    for node in nodes:
        if node.get(key) == value:
            return node

    return None

def _normalize(value):
    """Normalize JSON values so they can be compared reliably."""
    if isinstance(value, dict):
        return {key: _normalize(value[key]) for key in sorted(value)}

    if isinstance(value, list):
        normalized = [_normalize(v) for v in value]
        return sorted( normalized, key=lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False) )

    return value

def _json_equal(a, b):
    return _normalize(a) == _normalize(b)

# ============================================================================
# Merge helpers
# ============================================================================

def _merge_list(a, b):
    """Merge two lists while removing duplicates."""
    result = copy.deepcopy(a or [])

    existing = { json.dumps(_normalize(item), sort_keys=True, ensure_ascii=False) for item in result }

    for item in b or []:
        key = json.dumps(_normalize(item), sort_keys=True, ensure_ascii=False)

        if key not in existing:
            result.append(copy.deepcopy(item))
            existing.add(key)

    return result

def merge_filters(target, source):
    """Merge filter definitions."""
    if not target:
        return copy.deepcopy(source)

    if not source:
        return copy.deepcopy(target)

    result = copy.deepcopy(target)

    for filter_name, values in source.items():
        result[filter_name] = _merge_list( result.get(filter_name, []), values or [] )

    return result

def merge_actions(target, source):
    """
    Merge action_allowed definitions.

    Existing actions are preserved.
    New actions are added.
    """
    if not target:
        return copy.deepcopy(source)

    if not source:
        return copy.deepcopy(target)

    result = copy.deepcopy(target)

    for action_name, action_value in source.items():
        if action_name not in result:
            result[action_name] = copy.deepcopy(action_value)

    return result

def merge_nodes(target_nodes, source_nodes, node_key, children_key):
    """Recursively merge hierarchical permission nodes."""
    for source_node in source_nodes or []:
        source_value = source_node.get(node_key)

        target_node = _find_node( target_nodes, node_key, source_value )

        if target_node is None:
            target_nodes.append(copy.deepcopy(source_node))
            continue

        target_node["permissions"] = _merge_list( target_node.get("permissions") or [], source_node.get("permissions") or [] )

        target_node["filters"] = merge_filters( target_node.get("filters"), source_node.get("filters") )

        target_node["allowed_actions"] = merge_actions( target_node.get("allowed_actions"), source_node.get("allowed_actions") )

        source_children = source_node.get(children_key, [])

        if not source_children:
            continue

        if children_key == "schemas":
            next_key, next_children = "schema", "tables"
        elif children_key == "tables":
            next_key, next_children = "table", "columns"
        elif children_key == "columns":
            next_key, next_children = "column", None
        else:
            next_key, next_children = None, None

        if next_key is not None:
            merge_nodes( target_node.setdefault(children_key, []), source_children, next_key, next_children )

def merge_permission_tree(target, source):
    """
    Merge source permission tree into target.

    This represents all permissions already installed in OPA.
    """
    for group_name, source_group in source.items():
        if group_name not in target:
            target[group_name] = copy.deepcopy(source_group)
            continue

        target_group = target[group_name]

        target_group["permissions"] = _merge_list( target_group.get("permissions") or [], source_group.get("permissions") or [] )

        target_group["filters"] = merge_filters( target_group.get("filters"), source_group.get("filters") )

        target_group["allowed_actions"] = merge_actions( target_group.get("allowed_actions"), source_group.get("allowed_actions") )

        merge_nodes( target_group.setdefault("catalogs", []), source_group.get("catalogs", []), "catalog", "schemas" )

# ============================================================================
# Loading existing permission trees
# ============================================================================

def load_existing_permission_trees(tree_directory, exclude_file=None):
    """Load and merge all existing permission-tree JSON files."""
    merged = {}

    if not os.path.exists(tree_directory):
        return merged

    for filename in os.listdir(tree_directory):
        if not filename.endswith(".json"):
            continue

        filepath = os.path.join(tree_directory, filename)

        if ( exclude_file is not None and os.path.abspath(filepath) == os.path.abspath(exclude_file) ):
            continue

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                tree = json.load(f)
        except Exception as e:
            print(f"Failed to read permission tree {filepath}: {e}")
            continue

        merge_permission_tree(merged, tree)

    return merged

# ============================================================================
# Get new permission tree
# ============================================================================

def get_new_permission_tree(new_tree_file, tree_directory):
    """
    Compare a newly generated permission tree against all
    previously generated/installed permission trees.

    Returns only permissions introduced by the new policy.
    """
    with open(new_tree_file, "r", encoding="utf-8") as f:
        new_tree = json.load(f)

    existing_tree = load_existing_permission_trees( tree_directory, exclude_file=new_tree_file )

    return subtract_permission_tree(new_tree, existing_tree)

# ============================================================================
# Subtraction helpers
# ============================================================================

def _subtract_list(new_list, old_list):
    """Return elements present in new_list but not in old_list."""
    if not new_list:
        return []

    old_normalized = { json.dumps(_normalize(item), sort_keys=True, ensure_ascii=False) for item in (old_list or []) }

    result = []

    for item in new_list:
        key = json.dumps( _normalize(item), sort_keys=True, ensure_ascii=False )

        if key not in old_normalized:
            result.append(copy.deepcopy(item))

    return result

def subtract_filters(new_filters, old_filters):
    """Return only filters that are not already present."""
    if not new_filters:
        return None

    if not old_filters:
        return copy.deepcopy(new_filters)

    result = {}

    for filter_name, new_values in new_filters.items():
        old_values = old_filters.get(filter_name, [])

        difference = _subtract_list( new_values or [], old_values or [] )

        if difference:
            result[filter_name] = difference

    return result if result else None

def subtract_action_allowed(new_actions, old_actions):
    """
    Return only actions that are not already represented.

    If an action exists in the old tree with a different definition,
    the new definition is retained.
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

        if not _json_equal(action_value, old_action):
            result[action_name] = copy.deepcopy(action_value)

    return result if result else None

# ============================================================================
# Recursive node subtraction
# ============================================================================

def subtract_nodes(new_nodes, old_nodes, node_key, children_key):
    """
    Recursively subtract hierarchical permission nodes.

    Hierarchy:
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

    old_nodes = old_nodes or []
    result = []

    for new_node in new_nodes:
        node_value = new_node.get(node_key)

        old_node = _find_node( old_nodes, node_key, node_value )

        if old_node is None:
            result.append(copy.deepcopy(new_node))
            continue

        diff_node = {}

        permission_diff = _subtract_list( new_node.get("permissions") or [], old_node.get("permissions") or [] )

        if permission_diff:
            diff_node["permissions"] = permission_diff

        filter_diff = subtract_filters( new_node.get("filters"), old_node.get("filters") )

        if filter_diff is not None:
            diff_node["filters"] = filter_diff

        action_diff = subtract_action_allowed( new_node.get("allowed_actions"), old_node.get("allowed_actions") )

        if action_diff:
            diff_node["allowed_actions"] = action_diff

        children = new_node.get(children_key, [])

        if children:
            if children_key == "schemas":
                child_key, next_children_key = "schema", "tables"
            elif children_key == "tables":
                child_key, next_children_key = "table", "columns"
            elif children_key == "columns":
                child_key, next_children_key = "column", None
            else:
                child_key, next_children_key = None, None

            if next_children_key is not None:
                child_diff = subtract_nodes( children, old_node.get(children_key, []), child_key, next_children_key )

                if child_diff:
                    diff_node[children_key] = child_diff

            else:
                old_children = old_node.get(children_key, [])
                column_diff = []

                for new_column in children:
                    column_name = new_column.get("column")

                    old_column = _find_node( old_children, "column", column_name )

                    if old_column is None:
                        column_diff.append(copy.deepcopy(new_column))
                        continue

                    column_result = {}

                    permission_diff = _subtract_list( new_column.get("permissions") or [], old_column.get("permissions") or [] )

                    if permission_diff:
                        column_result["permissions"] = permission_diff

                    filter_diff = subtract_filters( new_column.get("filters"), old_column.get("filters") )

                    if filter_diff is not None:
                        column_result["filters"] = filter_diff

                    action_diff = subtract_action_allowed( new_column.get("allowed_actions"), old_column.get("allowed_actions") )

                    if action_diff:
                        column_result["allowed_actions"] = action_diff

                    if column_result:
                        column_result["column"] = column_name
                        column_diff.append(column_result)

                if column_diff:
                    diff_node[children_key] = column_diff

        if diff_node:
            diff_node[node_key] = node_value

            ordered_node = { node_key: diff_node.pop(node_key), **diff_node }

            result.append(ordered_node)

    return result

# ============================================================================
# Permission tree subtraction
# ============================================================================

def subtract_permission_tree(new_tree, existing_tree):
    """
    Return only the permissions, filters, and actions that exist
    in new_tree but are not already present in existing_tree.
    """
    result = {}

    for group_name, new_group in new_tree.items():
        old_group = existing_tree.get(group_name)

        if old_group is None:
            result[group_name] = copy.deepcopy(new_group)
            continue

        diff_group = {}

        permission_diff = _subtract_list( new_group.get("permissions") or [], old_group.get("permissions") or [] )

        if permission_diff:
            diff_group["permissions"] = permission_diff

        filter_diff = subtract_filters( new_group.get("filters"), old_group.get("filters") )

        if filter_diff is not None:
            diff_group["filters"] = filter_diff

        action_diff = subtract_action_allowed( new_group.get("allowed_actions"), old_group.get("allowed_actions") )

        if action_diff:
            diff_group["allowed_actions"] = action_diff

        catalog_diff = subtract_nodes( new_group.get("catalogs", []), old_group.get("catalogs", []), "catalog", "schemas" )

        if catalog_diff:
            diff_group["catalogs"] = catalog_diff

        if diff_group:
            result[group_name] = diff_group

    return result

# ============================================================================
# Build complete permission tree
# ============================================================================

def build_complete_permission_tree( tree_permission_dir, tree_structure_path, output_rego_dir, check_for_action_path, security_groups_path ):
    """
    Build the cumulative permission tree from all accepted
    Rego policies currently present in output_rego_dir.
    """
    os.makedirs(tree_permission_dir, exist_ok=True)

    if not os.path.exists(output_rego_dir):
        return {}

    rego_files = [ filename for filename in os.listdir(output_rego_dir) if filename.endswith(".rego") ]

    if not rego_files:
        return {}

    complete_tree = build_permission_tree_from_directory( opa_directory=output_rego_dir, action_permissions_file=check_for_action_path, security_groups_file=security_groups_path )

    with open(tree_structure_path, "w", encoding="utf-8") as f:
        json.dump( complete_tree, f, indent=2, ensure_ascii=False )

    return complete_tree

# ============================================================================
# Compare candidate against cumulative tree
# ============================================================================

def get_permission_difference(candidate_tree_file, tree_permission_dir, tree_structure_path):
    """
    Compare the candidate tree against the current cumulative tree.
    """
    comparison_dir = os.path.join(tree_permission_dir, "_comparison")
    os.makedirs(comparison_dir, exist_ok=True)

    try:
        if not os.path.exists(tree_structure_path):
            return load_json(candidate_tree_file)

        existing_tree_file = os.path.join(comparison_dir, "tree_structure.json")

        with open(tree_structure_path, "r", encoding="utf-8") as source:
            existing_tree = json.load(source)

        with open(existing_tree_file, "w", encoding="utf-8") as destination:
            json.dump(existing_tree, destination, indent=2, ensure_ascii=False)

        return get_new_permission_tree( new_tree_file=candidate_tree_file, tree_directory=comparison_dir )

    finally:
        if os.path.exists(comparison_dir):
            for filename in os.listdir(comparison_dir):
                file_path = os.path.join(comparison_dir, filename)

                if os.path.isfile(file_path):
                    os.remove(file_path)

            try:
                os.rmdir(comparison_dir)
            except OSError:
                pass
