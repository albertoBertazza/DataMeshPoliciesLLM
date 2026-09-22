import re
from typing import Any, Dict, List

BASE_PERMISSIONS = { "AccessCatalog", "ExecuteQuery"}

MASK_FILTER_PERMISSIONS = { "GetColumnMask", "GetRowFilters"}

# ============================================================================
# Canonical hierarchy
#
# 0 = root
# 1 = catalog
# 2 = schema
# 3 = table / view / materialized view
# 4 = column
# ============================================================================

RESOURCE_DEPTH = { "root": 0, "catalog": 1, "schema": 2, "table": 3, "view": 3, "materialized_view": 3, "column": 4}

def _snake(name: str) -> str:
    return re.sub( r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")

# ============================================================================
# Permission helpers
# ============================================================================

def _base_permissions( check_for_action: Dict[str, List[str]]) -> set:

    lists = [ set(value) for value in check_for_action.values() if isinstance(value, list) ]

    common = ( set.intersection(*lists) if lists else set() )

    return common | BASE_PERMISSIONS

def _permissions_for( actions: List[str], check_for_action: Dict[str, List[str]]) -> List[str]:

    result: List[str] = []

    for action in actions:

        if action not in check_for_action:
            raise ValueError( f"Action {action!r} not in checkForAction." )

        for permission in check_for_action[action]:

            if permission not in result:
                result.append(permission)

    return result

# ============================================================================
# Resource construction
# ============================================================================

def _nested_resource( resource: Dict[str, Any]):
    catalog = str( resource.get("catalog") or "" ).strip()

    schema = str( resource.get("schema") or "" ).strip()

    table = str( resource.get("table") or "" ).strip()

    column = str( resource.get("column") or "" ).strip()

    if not catalog:
        return "root", { "root": {} }

    catalog_node: Dict[str, Any] = { "catalogName": catalog }

    resource_type = "catalog"

    if schema:

        schema_node: Dict[str, Any] = { "schemaName": schema }

        catalog_node["schemas"] = [ schema_node ]

        resource_type = "schema"

        if table:

            table_node: Dict[str, Any] = { "tableName": table }

            schema_node["tables"] = [ table_node ]

            resource_type = "table"

            if column:

                table_node["columns"] = [ { "columnName": column } ]

                resource_type = "column"

    return resource_type, { "catalogs": [ catalog_node ] }

# ============================================================================
# Permission placement
# ============================================================================

def _permission_placement_depth( permission: str, rule_depth: int, permission_depth: Dict[str, int]) -> int:

    if permission not in permission_depth:
        raise ValueError( f"Permission {permission!r} has no entry " f"in permission_depth." )

    maximum_depth = permission_depth[ permission ]

    if maximum_depth < 0 or maximum_depth > 4:
        raise ValueError( f"Invalid depth for permission " f"{permission!r}: {maximum_depth}" )

    return min( rule_depth, maximum_depth)

def _add_permission_at_depth( resource_values: Dict[str, Any], permission: str, effect: str, placement_depth: int) -> None:

    if effect not in ( "allow", "deny"):
        raise ValueError( f"Invalid permission effect: {effect!r}" )

    # ------------------------------------------------------------------------
    # Depth 0 = root
    # ------------------------------------------------------------------------

    if placement_depth == 0:

        root_node = resource_values.setdefault( "root", {})

        permissions = root_node.setdefault( "permissions", { "allow": [], "deny": []})

        if permission not in permissions[effect]:
            permissions[effect].append( permission )

        return

    # ------------------------------------------------------------------------
    # Depth 1 = catalog
    # ------------------------------------------------------------------------

    catalogs = resource_values.get( "catalogs", [])

    if not catalogs:
        raise ValueError( f"Cannot place permission {permission!r}: " "resource has no catalog." )

    catalog_node = catalogs[0]

    def add_to_node( node: Dict[str, Any]) -> None:

        permissions = node.setdefault( "permissions", { "allow": [], "deny": []})

        if permission not in permissions[effect]:
            permissions[effect].append( permission )

    if placement_depth == 1:

        add_to_node( catalog_node )

        return

    # ------------------------------------------------------------------------
    # Depth 2 = schema
    # ------------------------------------------------------------------------

    schemas = catalog_node.get( "schemas", [])

    if placement_depth == 2:

        if not schemas:
            raise ValueError( f"Cannot place permission {permission!r}: " "resource has no schema." )

        add_to_node( schemas[0] )

        return

    # ------------------------------------------------------------------------
    # Depth 3 = table / view / materialized view
    # ------------------------------------------------------------------------

    if placement_depth == 3:

        if not schemas:
            raise ValueError( f"Cannot place permission {permission!r}: " "resource has no schema." )

        tables = schemas[0].get( "tables", [])

        if not tables:
            raise ValueError( f"Cannot place permission {permission!r}: " "resource has no table." )

        add_to_node( tables[0] )

        return

    # ------------------------------------------------------------------------
    # Depth 4 = column
    # ------------------------------------------------------------------------

    if placement_depth == 4:

        if not schemas:
            raise ValueError( f"Cannot place permission {permission!r}: " "resource has no schema." )

        tables = schemas[0].get( "tables", [])

        if not tables:
            raise ValueError( f"Cannot place permission {permission!r}: " "resource has no table." )

        columns = tables[0].get( "columns", [])

        if not columns:
            raise ValueError( f"Cannot place permission {permission!r}: " "resource has no column." )

        add_to_node( columns[0] )

        return

    raise ValueError( f"Invalid placement depth: " f"{placement_depth}" )

def _place_permissions( permissions: List[str], effect: str, rule_depth: int, resource_values: Dict[str, Any], permission_depth: Dict[str, int]) -> None:

    for permission in permissions:

        placement_depth = _permission_placement_depth( permission=permission, rule_depth=rule_depth, permission_depth=permission_depth)

        _add_permission_at_depth( resource_values=resource_values, permission=permission, effect=effect, placement_depth=placement_depth)

# ============================================================================
# Column masks
# ============================================================================

def _add_column_mask( resource_values: Dict[str, Any], column_mask: Dict[str, str]) -> None:

    catalogs = resource_values.get( "catalogs", [])

    if not catalogs:
        raise ValueError( "Column mask requires a catalog." )

    schemas = catalogs[0].get( "schemas", [])

    if not schemas:
        raise ValueError( "Column mask requires a schema." )

    tables = schemas[0].get( "tables", [])

    if not tables:
        raise ValueError( "Column mask requires a table." )

    columns = tables[0].get( "columns", [])

    if not columns:
        raise ValueError( "Column mask requires a column." )

    column_node = columns[0]

    masks = column_node.setdefault( "column_masks", [])

    if column_mask not in masks:
        masks.append( column_mask )

# ============================================================================
# Row filters
# ============================================================================

def _add_row_filter( resource_values: Dict[str, Any], row_filter: str) -> None:

    catalogs = resource_values.get( "catalogs", [])

    if not catalogs:
        raise ValueError( "Row filter requires a catalog." )

    schemas = catalogs[0].get( "schemas", [])

    if not schemas:
        raise ValueError( "Row filter requires a schema." )

    tables = schemas[0].get( "tables", [])

    if not tables:
        raise ValueError( "Row filter requires a table." )

    table_node = tables[0]

    filters = table_node.setdefault( "row_filters", [])

    if row_filter not in filters:
        filters.append( row_filter )

# ============================================================================
# Main extractor
# ============================================================================

def build_intermediate_representation( explanation: Dict[str, Any], check_for_action: Dict[str, List[str]], permission_depth: Dict[str, int]) -> Dict[str, Any]:

    group = explanation.get( "securityGroup" )

    if not group:
        raise ValueError( "No security group in explanation." )

    allowed_actions = ( explanation.get("allowed") or [] )

    denied_actions = ( explanation.get("deny") or [] )

    column_mask = explanation.get( "columnMask" )

    row_filter = explanation.get( "rowFilter" )

    if isinstance(column_mask, str):
        column_mask = ( column_mask.strip() or None )

    if isinstance(row_filter, str):
        row_filter = ( row_filter.strip() or None )

    has_mask = bool(column_mask)
    has_filter = bool(row_filter)

    if ( not allowed_actions and not denied_actions and not has_mask and not has_filter ):
        raise ValueError( "Explanation contains no allowed/denied action, " "column mask, or row filter." )

    # ------------------------------------------------------------------------
    # Resource
    # ------------------------------------------------------------------------

    resource = ( explanation.get("resource") or {} )

    resource_type, resource_values = _nested_resource( resource )

    rule_depth = RESOURCE_DEPTH[ resource_type ]

    # ------------------------------------------------------------------------
    # ALLOW
    # ------------------------------------------------------------------------

    allow = [ permission for permission in _permissions_for( allowed_actions, check_for_action) if permission not in MASK_FILTER_PERMISSIONS ]

    # ------------------------------------------------------------------------
    # DENY
    # ------------------------------------------------------------------------

    base = _base_permissions( check_for_action )

    deny: List[str] = []

    for action in denied_actions:

        specific = [ permission for permission in _permissions_for( [action], check_for_action) if ( permission not in base and permission not in MASK_FILTER_PERMISSIONS ) ]

        if not specific:
            raise ValueError( f"Denied action {action!r} has no " "distinguishing permission." )

        for permission in specific:

            if permission not in deny:
                deny.append( permission )

    # ------------------------------------------------------------------------
    # Special effect permissions
    # ------------------------------------------------------------------------

    if has_mask:

        if "GetColumnMask" not in allow:
            allow.append( "GetColumnMask" )

    if has_filter:

        if "GetRowFilters" not in allow:
            allow.append( "GetRowFilters" )

    # ------------------------------------------------------------------------
    # Conflicts
    # ------------------------------------------------------------------------

    conflicts = ( set(allow) & set(deny) )

    if conflicts:
        raise ValueError( "Permission both allowed and denied: " + ", ".join( sorted(conflicts) ) )

    # ------------------------------------------------------------------------
    # Place ALLOW
    # ------------------------------------------------------------------------

    normal_allow = [ permission for permission in allow if permission not in MASK_FILTER_PERMISSIONS ]

    _place_permissions( permissions=normal_allow, effect="allow", rule_depth=rule_depth, resource_values=resource_values, permission_depth=permission_depth)

    # ------------------------------------------------------------------------
    # Place DENY
    # ------------------------------------------------------------------------

    _place_permissions( permissions=deny, effect="deny", rule_depth=rule_depth, resource_values=resource_values, permission_depth=permission_depth)

    # ------------------------------------------------------------------------
    # Column mask
    #
    # A column mask is always attached to the concrete column.
    # GetColumnMask itself has depth 4.
    # ------------------------------------------------------------------------

    if has_mask:

        column_name = str( resource.get("column") or "" ).strip()

        if not column_name:
            raise ValueError( "A column mask requires a specific resource column." )

        mask_expression = str( column_mask or "" ).strip()

        if not mask_expression:
            raise ValueError( "A column mask requires a non-empty expression." )

        mask_depth = _permission_placement_depth( permission="GetColumnMask", rule_depth=rule_depth, permission_depth=permission_depth)

        if mask_depth != 4:
            raise ValueError( "GetColumnMask must resolve to column depth 4." )

        _add_column_mask( resource_values=resource_values, column_mask={ "column": column_name, "expression": mask_expression})

    # ------------------------------------------------------------------------
    # Row filter
    #
    # A row filter is attached to a table.
    # GetRowFilters has depth 3.
    # ------------------------------------------------------------------------

    if has_filter:

        table_name = str( resource.get("table") or "" ).strip()

        if not table_name:
            raise ValueError( "A row filter requires a specific table." )

        filter_expression = str( row_filter or "" ).strip()

        if not filter_expression:
            raise ValueError( "A row filter requires a non-empty expression." )

        filter_depth = _permission_placement_depth( permission="GetRowFilters", rule_depth=rule_depth, permission_depth=permission_depth)

        if filter_depth != 3:
            raise ValueError( "GetRowFilters must resolve to table depth 3." )

        _add_row_filter( resource_values=resource_values, row_filter=filter_expression)

    # ------------------------------------------------------------------------
    # FINAL IR
    # ------------------------------------------------------------------------

    return {
        "subject_attribute": "groups",
        "subject_value": _snake(group),
        "resource_type": resource_type,
        "resource_values": resource_values,

        # Effects are stored locally inside resource_values.
        # These remain empty at the top level.
        "column_masks": [],
        "row_filters": [],
    }
