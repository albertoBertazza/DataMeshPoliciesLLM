import re
from typing import Any, Dict, List


BASE_PERMISSIONS = {
    "AccessCatalog",
    "ExecuteQuery",
}

MASK_FILTER_PERMISSIONS = {
    "GetColumnMask",
    "GetRowFilters",
}


# ============================================================================
# Canonical hierarchy
#
# 0 = root
# 1 = catalog
# 2 = schema
# 3 = table / view / materialized view
# 4 = column
# ============================================================================

RESOURCE_DEPTH = {
    "root": 0,
    "catalog": 1,
    "schema": 2,
    "table": 3,
    "view": 3,
    "materialized_view": 3,
    "column": 4,
}


# ============================================================================
# Permission helpers
# ============================================================================

def _base_permissions(
    check_for_action: Dict[str, List[str]]
) -> set:
    lists = [
        set(value)
        for value in check_for_action.values()
        if isinstance(value, list)
    ]

    common = set.intersection(*lists) if lists else set()

    return common | BASE_PERMISSIONS


def _permissions_for(
    actions: List[str],
    check_for_action: Dict[str, List[str]]
) -> List[str]:

    result: List[str] = []

    for action in actions:

        if action not in check_for_action:
            raise ValueError(
                f"Action {action!r} not in checkForAction."
            )

        for permission in check_for_action[action]:

            if permission not in result:
                result.append(permission)

    return result


# ============================================================================
# Resource construction
# ============================================================================

def _nested_resource(
    resource: Dict[str, Any]
):
    catalog = str(
        resource.get("catalog") or ""
    ).strip()

    schema = str(
        resource.get("schema") or ""
    ).strip()

    table = str(
        resource.get("table") or ""
    ).strip()

    column = str(
        resource.get("column") or ""
    ).strip()

    # ------------------------------------------------------------------------
    # Root
    # ------------------------------------------------------------------------

    if not catalog:
        return "root", {
            "root": {}
        }

    # ------------------------------------------------------------------------
    # Catalog
    # ------------------------------------------------------------------------

    catalog_node: Dict[str, Any] = {
        "catalogName": catalog
    }

    resource_type = "catalog"

    # ------------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------------

    if schema:

        schema_node: Dict[str, Any] = {
            "schemaName": schema
        }

        catalog_node["schemas"] = [
            schema_node
        ]

        resource_type = "schema"

        # --------------------------------------------------------------------
        # Table
        # --------------------------------------------------------------------

        if table:

            table_node: Dict[str, Any] = {
                "tableName": table
            }

            schema_node["tables"] = [
                table_node
            ]

            resource_type = "table"

            # ----------------------------------------------------------------
            # Column
            # ----------------------------------------------------------------

            if column:

                table_node["columns"] = [
                    {
                        "columnName": column
                    }
                ]

                resource_type = "column"

    return resource_type, {
        "catalogs": [
            catalog_node
        ]
    }


# ============================================================================
# Permission placement
# ============================================================================

def _permission_placement_depth(
    permission: str,
    rule_depth: int,
    permission_depth: Dict[str, int],
) -> int:

    if permission not in permission_depth:
        raise ValueError(
            f"Permission {permission!r} has no entry "
            f"in permission_depth."
        )

    maximum_depth = permission_depth[permission]

    if maximum_depth < 0 or maximum_depth > 4:
        raise ValueError(
            f"Invalid depth for permission "
            f"{permission!r}: {maximum_depth}"
        )

    return min(
        rule_depth,
        maximum_depth
    )


def _add_permission_at_depth(
    resource_values: Dict[str, Any],
    permission: str,
    effect: str,
    placement_depth: int,
) -> None:

    if effect not in ("allow", "deny"):
        raise ValueError(
            f"Invalid permission effect: {effect!r}"
        )

    # ------------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------------

    def add_to_node(
        node: Dict[str, Any]
    ) -> None:

        permissions = node.setdefault(
            "permissions",
            {
                "allow": [],
                "deny": [],
            }
        )

        if not isinstance(permissions, dict):
            raise ValueError(
                "Resource permissions must be an object."
            )

        permissions.setdefault("allow", [])
        permissions.setdefault("deny", [])

        if permission not in permissions[effect]:
            permissions[effect].append(permission)

    # ------------------------------------------------------------------------
    # Root
    # ------------------------------------------------------------------------

    if placement_depth == 0:

        root_node = resource_values.setdefault(
            "root",
            {}
        )

        add_to_node(root_node)

        return

    # ------------------------------------------------------------------------
    # Catalog
    # ------------------------------------------------------------------------

    catalogs = resource_values.get(
        "catalogs",
        []
    )

    if not catalogs:
        raise ValueError(
            f"Cannot place permission {permission!r}: "
            "resource has no catalog."
        )

    catalog_node = catalogs[0]

    if placement_depth == 1:

        add_to_node(catalog_node)

        return

    # ------------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------------

    schemas = catalog_node.get(
        "schemas",
        []
    )

    if not schemas:
        raise ValueError(
            f"Cannot place permission {permission!r}: "
            "resource has no schema."
        )

    schema_node = schemas[0]

    if placement_depth == 2:

        add_to_node(schema_node)

        return

    # ------------------------------------------------------------------------
    # Table
    # ------------------------------------------------------------------------

    tables = schema_node.get(
        "tables",
        []
    )

    if not tables:
        raise ValueError(
            f"Cannot place permission {permission!r}: "
            "resource has no table."
        )

    table_node = tables[0]

    if placement_depth == 3:

        add_to_node(table_node)

        return

    # ------------------------------------------------------------------------
    # Column
    # ------------------------------------------------------------------------

    if placement_depth == 4:

        columns = table_node.get(
            "columns",
            []
        )

        if not columns:
            raise ValueError(
                f"Cannot place permission {permission!r}: "
                "resource has no column."
            )

        add_to_node(columns[0])

        return

    raise ValueError(
        f"Invalid placement depth: {placement_depth}"
    )


def _place_permissions(
    permissions: List[str],
    effect: str,
    rule_depth: int,
    resource_values: Dict[str, Any],
    permission_depth: Dict[str, int],
) -> None:

    for permission in permissions:

        placement_depth = _permission_placement_depth(
            permission=permission,
            rule_depth=rule_depth,
            permission_depth=permission_depth,
        )

        _add_permission_at_depth(
            resource_values=resource_values,
            permission=permission,
            effect=effect,
            placement_depth=placement_depth,
        )


# ============================================================================
# Metadata visibility filters
# ============================================================================

FILTER_DEPTH = {
    "FilterCatalogs": 0,
    "FilterSchemas": 1,
    "FilterTables": 2,
    "FilterColumns": 3,
}


# Canonical names inside the extracted IR.
#
# The merger can later convert these to:
#
# filter_catalogs
# filter_schemas
# filter_tables
# filter_columns
#
FILTER_KEY = {
    "FilterCatalogs": "FilterCatalogs",
    "FilterSchemas": "FilterSchemas",
    "FilterTables": "FilterTables",
    "FilterColumns": "FilterColumns",
}


def _add_filter_at_depth(
    resource_values: Dict[str, Any],
    filter_name: str,
    filter_value: str,
    effect: str,
    placement_depth: int,
    security_group: str,
) -> None:
    """
    Store a metadata visibility declaration at the appropriate hierarchy
    level, scoped to the security group.

    FilterCatalogs -> root
    FilterSchemas  -> catalog
    FilterTables   -> schema
    FilterColumns  -> table
    """

    if effect not in ("allowed", "deny"):
        raise ValueError(
            f"Invalid filter effect: {effect!r}"
        )

    if filter_name not in FILTER_KEY:
        raise ValueError(
            f"Unknown metadata filter: {filter_name!r}"
        )

    filter_key = FILTER_KEY[filter_name]

    if not filter_value:
        return

    if not security_group:
        raise ValueError(
            "Security group is required for metadata visibility filters."
        )

    def add_to_node(node: Dict[str, Any]) -> None:

        filters = node.setdefault(
            filter_key,
            {}
        )

        if not isinstance(filters, dict):
            raise ValueError(
                f"'{filter_key}' must be an object."
            )

        group_filter = filters.setdefault(
            security_group,
            {
                "allowed": [],
                "deny": [],
            }
        )

        if not isinstance(group_filter, dict):
            raise ValueError(
                f"'{filter_key}.{security_group}' must be an object."
            )

        group_filter.setdefault("allowed", [])
        group_filter.setdefault("deny", [])

        if filter_value not in group_filter[effect]:
            group_filter[effect].append(filter_value)

    # ------------------------------------------------------------------------
    # Root
    # ------------------------------------------------------------------------

    if placement_depth == 0:

        root_node = resource_values.setdefault(
            "root",
            {}
        )

        add_to_node(root_node)
        return

    # ------------------------------------------------------------------------
    # Catalog
    # ------------------------------------------------------------------------

    catalogs = resource_values.get("catalogs", [])

    if not catalogs:
        raise ValueError(
            f"Cannot place {filter_name!r}: "
            "resource has no catalog."
        )

    catalog_node = catalogs[0]

    if placement_depth == 1:

        add_to_node(catalog_node)
        return

    # ------------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------------

    schemas = catalog_node.get("schemas", [])

    if not schemas:
        raise ValueError(
            f"Cannot place {filter_name!r}: "
            "resource has no schema."
        )

    schema_node = schemas[0]

    if placement_depth == 2:

        add_to_node(schema_node)
        return

    # ------------------------------------------------------------------------
    # Table
    # ------------------------------------------------------------------------

    tables = schema_node.get("tables", [])

    if not tables:
        raise ValueError(
            f"Cannot place {filter_name!r}: "
            "resource has no table."
        )

    table_node = tables[0]

    if placement_depth == 3:

        add_to_node(table_node)
        return

    raise ValueError(
        f"Invalid filter placement depth: {placement_depth}"
    )


def _place_visibility_filters(
    visibility_filters: Dict[str, Any],
    rule_depth: int,
    resource_values: Dict[str, Any],
    security_group: str
) -> None:
    """
    Place metadata visibility declarations.

    Placement:

        FilterCatalogs -> min(rule_depth, 0)
        FilterSchemas  -> min(rule_depth, 1)
        FilterTables   -> min(rule_depth, 2)
        FilterColumns  -> min(rule_depth, 3)
    """

    for filter_name, filter_depth in FILTER_DEPTH.items():

        value = visibility_filters.get(
            filter_name
        )

        if not isinstance(value, dict):
            continue

        allowed = value.get(
            "allowed",
            []
        )

        denied = value.get(
            "deny",
            []
        )

        if not isinstance(allowed, list):
            raise ValueError(
                f"{filter_name}.allowed must be a list."
            )

        if not isinstance(denied, list):
            raise ValueError(
                f"{filter_name}.deny must be a list."
            )

        placement_depth = min(
            rule_depth,
            filter_depth,
        )

        # --------------------------------------------------------------------
        # Allowed
        # --------------------------------------------------------------------

        for filter_value in allowed:

            filter_value = str(
                filter_value
            ).strip()

            if not filter_value:
                continue

            _add_filter_at_depth(
                resource_values=resource_values,
                filter_name=filter_name,
                filter_value=filter_value,
                effect="allowed",
                placement_depth=placement_depth,
                security_group=security_group,
            )

        # --------------------------------------------------------------------
        # Denied
        # --------------------------------------------------------------------

        for filter_value in denied:

            filter_value = str(
                filter_value
            ).strip()

            if not filter_value:
                continue

            _add_filter_at_depth(
                resource_values=resource_values,
                filter_name=filter_name,
                filter_value=filter_value,
                effect="deny",
                placement_depth=placement_depth,
                security_group=security_group,
            )


# ============================================================================
# Semantic validation
# ============================================================================

def validate_filter_semantics(
    explanation: Dict[str, Any]
) -> None:
    """
    Validate that row filters and column masks are attached to resources
    where they make semantic sense.

    IMPORTANT:

    A metadata visibility filter such as:

        FilterSchemas.deny = ["hr"]

    is NOT a row filter.

    A row filter is only valid when a specific table is targeted.
    """

    resource = explanation.get(
        "resource"
    ) or {}

    if not isinstance(resource, dict):
        raise ValueError(
            "'resource' must be an object."
        )

    catalog = str(
        resource.get("catalog") or ""
    ).strip()

    schema = str(
        resource.get("schema") or ""
    ).strip()

    table = str(
        resource.get("table") or ""
    ).strip()

    column = str(
        resource.get("column") or ""
    ).strip()

    row_filter = explanation.get(
        "row_filter"
    )

    if isinstance(row_filter, str):
        row_filter = row_filter.strip() or None

    # ------------------------------------------------------------------------
    # Row filter
    # ------------------------------------------------------------------------

    if row_filter:

        if not table:
            raise ValueError(
                "Invalid row_filter: row filters require "
                "a specific table."
            )

        if not schema:
            raise ValueError(
                "Invalid row_filter: a table requires "
                "a schema."
            )

        if not catalog:
            raise ValueError(
                "Invalid row_filter: a table requires "
                "a catalog."
            )

    # ------------------------------------------------------------------------
    # Column masks
    # ------------------------------------------------------------------------

    column_masks = explanation.get(
        "column_masks"
    ) or {}

    if not isinstance(column_masks, dict):
        raise ValueError(
            "'column_masks' must be an object."
        )

    if column_masks:

        if not table:
            raise ValueError(
                "Invalid column_masks: column masks require "
                "a specific table."
            )

        if not schema:
            raise ValueError(
                "Invalid column_masks: a table requires "
                "a schema."
            )

        if not catalog:
            raise ValueError(
                "Invalid column_masks: a table requires "
                "a catalog."
            )

        if column:
            # If a specific column is targeted, the mask should normally
            # refer to that column.
            unknown_columns = (
                set(column_masks.keys()) - {column}
            )

            if unknown_columns:
                raise ValueError(
                    "Column mask targets columns "
                    f"{sorted(unknown_columns)} but the resource targets "
                    f"column {column!r}."
                )


# ============================================================================
# Column masks
# ============================================================================

def _add_column_mask(
    resource_values: Dict[str, Any],
    column_masks: Dict[str, str],
) -> None:

    catalogs = resource_values.get(
        "catalogs",
        []
    )

    if not catalogs:
        raise ValueError(
            "Column mask requires a catalog."
        )

    schemas = catalogs[0].get(
        "schemas",
        []
    )

    if not schemas:
        raise ValueError(
            "Column mask requires a schema."
        )

    tables = schemas[0].get(
        "tables",
        []
    )

    if not tables:
        raise ValueError(
            "Column mask requires a table."
        )

    columns = tables[0].get(
        "columns",
        []
    )

    if not columns:
        raise ValueError(
            "Column mask requires a column."
        )

    # ------------------------------------------------------------------------
    # Important:
    #
    # column_masks belong to the column node.
    # ------------------------------------------------------------------------

    for column_node in columns:

        column_name = column_node.get(
            "columnName"
        )

        if not column_name:
            continue

        if column_name not in column_masks:
            continue

        expression = column_masks[column_name]

        masks = column_node.setdefault(
            "column_masks",
            {}
        )

        if not isinstance(masks, dict):
            raise ValueError(
                "Column node 'column_masks' must be an object."
            )

        masks[column_name] = expression


# ============================================================================
# Row filters
# ============================================================================

def _add_row_filter(
    resource_values: Dict[str, Any],
    row_filter: str
) -> None:

    catalogs = resource_values.get(
        "catalogs",
        []
    )

    if not catalogs:
        raise ValueError(
            "Row filter requires a catalog."
        )

    schemas = catalogs[0].get(
        "schemas",
        []
    )

    if not schemas:
        raise ValueError(
            "Row filter requires a schema."
        )

    tables = schemas[0].get(
        "tables",
        []
    )

    if not tables:
        raise ValueError(
            "Row filter requires a table."
        )

    table_node = tables[0]

    filters = table_node.setdefault(
        "row_filters",
        []
    )

    if not isinstance(filters, list):
        raise ValueError(
            "Table node 'row_filters' must be a list."
        )

    if row_filter not in filters:
        filters.append(row_filter)


# ============================================================================
# Main extractor
# ============================================================================

def build_intermediate_representation(
    explanation: Dict[str, Any],
    check_for_action: Dict[str, List[str]],
    permission_depth: Dict[str, int],
) -> Dict[str, Any]:

    if not isinstance(explanation, dict):
        raise ValueError(
            "Explanation must be an object."
        )

    # =========================================================================
    # Security group
    # =========================================================================

    group = explanation.get(
        "securityGroup"
    )

    if not group:
        raise ValueError(
            "No security group in explanation."
        )

    # =========================================================================
    # IMPORTANT:
    #
    # Validate semantic relationships BEFORE building the IR.
    #
    # This catches:
    #
    #     row_filter + schema-only resource
    #
    # before _add_row_filter() is called.
    # =========================================================================

    validate_filter_semantics(
        explanation
    )

    # =========================================================================
    # Actions
    # =========================================================================

    allowed_actions = explanation.get(
        "allowed"
    ) or []

    denied_actions = explanation.get(
        "deny"
    ) or []

    if not isinstance(allowed_actions, list):
        raise ValueError(
            "'allowed' must be a list."
        )

    if not isinstance(denied_actions, list):
        raise ValueError(
            "'deny' must be a list."
        )

    # =========================================================================
    # Metadata visibility filters
    # =========================================================================

    visibility_filters: Dict[str, Dict[str, List[str]]] = {}

    for filter_name in FILTER_DEPTH:

        value = explanation.get(
            filter_name,
            {
                "allowed": [],
                "deny": [],
            }
        )

        if value is None:
            value = {
                "allowed": [],
                "deny": [],
            }

        if not isinstance(value, dict):
            raise ValueError(
                f"'{filter_name}' must be an object."
            )

        allowed_values = value.get(
            "allowed",
            []
        )

        denied_values = value.get(
            "deny",
            []
        )

        if not isinstance(allowed_values, list):
            raise ValueError(
                f"{filter_name}.allowed must be a list."
            )

        if not isinstance(denied_values, list):
            raise ValueError(
                f"{filter_name}.deny must be a list."
            )

        # --------------------------------------------------------------------
        # Normalize
        # --------------------------------------------------------------------

        allowed_values = [
            str(value).strip()
            for value in allowed_values
            if str(value).strip()
        ]

        denied_values = [
            str(value).strip()
            for value in denied_values
            if str(value).strip()
        ]

        # --------------------------------------------------------------------
        # Same value cannot be both allowed and denied locally.
        # --------------------------------------------------------------------

        conflicts = (
            set(allowed_values)
            & set(denied_values)
        )

        if conflicts:
            raise ValueError(
                f"{filter_name} contains values in both "
                f"'allowed' and 'deny': "
                + ", ".join(sorted(conflicts))
            )

        visibility_filters[filter_name] = {
            "allowed": allowed_values,
            "deny": denied_values,
        }

    has_visibility_filter = any(
        value["allowed"] or value["deny"]
        for value in visibility_filters.values()
    )

    # =========================================================================
    # Row filter
    # =========================================================================

    row_filter = explanation.get(
        "row_filter"
    )

    if isinstance(row_filter, str):
        row_filter = row_filter.strip() or None

    elif row_filter is not None:
        raise ValueError(
            "'row_filter' must be a string or null."
        )

    # =========================================================================
    # Column masks
    # =========================================================================

    column_masks = explanation.get(
        "column_masks"
    ) or {}

    if not isinstance(column_masks, dict):
        raise ValueError(
            "'column_masks' must be an object."
        )

    normalized_column_masks: Dict[str, str] = {}

    for column_name, expression in column_masks.items():

        column_name = str(
            column_name
        ).strip()

        if not column_name:
            raise ValueError(
                "Column mask contains an empty column name."
            )

        if expression is None:
            raise ValueError(
                f"Column mask for {column_name!r} "
                "has a null expression."
            )

        expression = str(
            expression
        ).strip()

        if not expression:
            raise ValueError(
                f"Column mask for {column_name!r} "
                "has an empty expression."
            )

        normalized_column_masks[
            column_name
        ] = expression

    column_masks = normalized_column_masks

    has_mask = bool(
        column_masks
    )

    has_filter = bool(
        row_filter
    )

    # =========================================================================
    # Empty explanation validation
    # =========================================================================

    if (
        not allowed_actions
        and not denied_actions
        and not has_mask
        and not has_filter
        and not has_visibility_filter
    ):
        raise ValueError(
            "Explanation contains no allowed/denied action, "
            "column mask, row filter, or metadata visibility filter."
        )

    # =========================================================================
    # Resource
    # =========================================================================

    resource = explanation.get(
        "resource"
    ) or {}

    if not isinstance(resource, dict):
        raise ValueError(
            "'resource' must be an object."
        )

    resource_type, resource_values = _nested_resource(
        resource
    )

    rule_depth = RESOURCE_DEPTH[
        resource_type
    ]

    # =========================================================================
    # Place metadata visibility filters
    # =========================================================================

    _place_visibility_filters(
        visibility_filters=visibility_filters,
        rule_depth=rule_depth,
        resource_values=resource_values,
        security_group=group,
    )

    # =========================================================================
    # ALLOW
    # =========================================================================

    allow = [
        permission
        for permission in _permissions_for(
            allowed_actions,
            check_for_action,
        )
        if permission not in MASK_FILTER_PERMISSIONS
    ]

    # =========================================================================
    # DENY
    # =========================================================================

    base = _base_permissions(
        check_for_action
    )

    deny: List[str] = []

    for action in denied_actions:

        specific = [
            permission
            for permission in _permissions_for(
                [action],
                check_for_action,
            )
            if (
                permission not in base
                and permission not in MASK_FILTER_PERMISSIONS
            )
        ]

        if not specific:
            raise ValueError(
                f"Denied action {action!r} has no "
                "distinguishing permission."
            )

        for permission in specific:

            if permission not in deny:
                deny.append(permission)

    # =========================================================================
    # Place permissions
    # =========================================================================

    _place_permissions(
        permissions=allow,
        effect="allow",
        rule_depth=rule_depth,
        resource_values=resource_values,
        permission_depth=permission_depth,
    )

    _place_permissions(
        permissions=deny,
        effect="deny",
        rule_depth=rule_depth,
        resource_values=resource_values,
        permission_depth=permission_depth,
    )

    # =========================================================================
    # Row filter
    # =========================================================================

    if row_filter:

        _add_row_filter(
            resource_values=resource_values,
            row_filter=row_filter,
        )

    # =========================================================================
    # Column masks
    # =========================================================================

    if column_masks:

        _add_column_mask(
            resource_values=resource_values,
            column_masks=column_masks,
        )

    # =========================================================================
    # Final IR
    # =========================================================================

    return {
        "subject_attribute": "groups",
        "subject_value": group,
        "resource_type": resource_type,
        "resource_values": resource_values,
        "column_masks": [],
        "row_filters": [],
    }