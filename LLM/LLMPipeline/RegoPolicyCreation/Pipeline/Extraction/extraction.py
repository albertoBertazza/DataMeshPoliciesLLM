import re
from typing import Any, Dict, List


# Permissions every ordinary action needs.
# These must not be denied indirectly when denying a specific action.
BASE_PERMISSIONS = {"AccessCatalog", "ExecuteQuery"}

# These permissions represent special Trino effects.
# They are emitted only when the corresponding effect exists.
MASK_FILTER_PERMISSIONS = {"GetColumnMask", "GetRowFilters"}


def _snake(name: str) -> str:
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        name.strip().lower()
    ).strip("_")


def _base_permissions(
    check_for_action: Dict[str, List[str]]
) -> set:
    lists = [
        set(v)
        for v in check_for_action.values()
        if isinstance(v, list)
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


def _nested_resource(resource: Dict[str, Any]):

    catalog = resource.get("catalog") or ""
    schema = resource.get("schema") or ""
    table = resource.get("table") or ""
    column = resource.get("column") or ""

    if not catalog:
        return "catalog", {"catalogs": []}

    catalog_node: Dict[str, Any] = {
        "catalogName": catalog
    }

    resource_type = "catalog"

    if schema:

        schema_node: Dict[str, Any] = {
            "schemaName": schema
        }

        catalog_node["schemas"] = [schema_node]

        resource_type = "schema"

        if table:

            table_node: Dict[str, Any] = {
                "tableName": table
            }

            schema_node["tables"] = [table_node]

            resource_type = "table"

            if column:

                table_node["columns"] = [column]

                resource_type = "column"

    return resource_type, {
        "catalogs": [catalog_node]
    }


def _normalize_mask(
    column_mask: Any
) -> Dict[str, str]:

    if not column_mask:
        return {}

    if isinstance(column_mask, dict):
        result = {}

        for column, expression in column_mask.items():

            if not isinstance(column, str):
                continue

            if not isinstance(expression, str):
                continue

            column = column.strip()
            expression = expression.strip()

            if column and expression:
                result[column] = expression

        return result

    # Single mask extracted by the LLM.
    # The resource column identifies which column it belongs to.
    if isinstance(column_mask, str):
        expression = column_mask.strip()

        if expression:
            return {
                "__resource_column__": expression
            }

    return {}


def build_intermediate_representation(
    explanation: Dict[str, Any],
    check_for_action: Dict[str, List[str]],
) -> Dict[str, Any]:

    group = explanation.get("securityGroup")

    if not group:
        raise ValueError(
            "No security group in explanation."
        )

    allowed_actions = explanation.get("allowed") or []
    denied_actions = explanation.get("deny") or []

    column_mask = explanation.get("columnMask")
    row_filter = explanation.get("rowFilter")

    # Normalize empty values.
    if isinstance(column_mask, str):
        column_mask = column_mask.strip() or None

    if isinstance(row_filter, str):
        row_filter = row_filter.strip() or None

    has_mask = bool(column_mask)
    has_filter = bool(row_filter)

    if (
        not allowed_actions
        and not denied_actions
        and not has_mask
        and not has_filter
    ):
        raise ValueError(
            "Explanation contains no allowed/denied action, "
            "column mask, or row filter."
        )

    base = _base_permissions(check_for_action)

    # ------------------------------------------------------------------
    # ALLOW
    # ------------------------------------------------------------------

    allow = [
        permission
        for permission in _permissions_for(
            allowed_actions,
            check_for_action
        )
        if permission not in MASK_FILTER_PERMISSIONS
    ]

    # ------------------------------------------------------------------
    # DENY
    #
    # Remove common/base permissions because denying a concrete action
    # must not implicitly deny AccessCatalog or ExecuteQuery.
    # ------------------------------------------------------------------

    deny: List[str] = []

    for action in denied_actions:

        specific = [
            permission
            for permission in _permissions_for(
                [action],
                check_for_action
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

    # ------------------------------------------------------------------
    # SPECIAL EFFECT PERMISSIONS
    #
    # These are added only when the actual effect exists.
    # ------------------------------------------------------------------

    if has_mask:

        if "GetColumnMask" not in allow:
            allow.append("GetColumnMask")

    if has_filter:

        if "GetRowFilters" not in allow:
            allow.append("GetRowFilters")

    # ------------------------------------------------------------------
    # Conflict detection
    # ------------------------------------------------------------------

    conflicts = set(allow) & set(deny)

    if conflicts:
        raise ValueError(
            "Permission both allowed and denied: "
            + ", ".join(sorted(conflicts))
        )

    # ------------------------------------------------------------------
    # Resource
    # ------------------------------------------------------------------

    resource = explanation.get("resource") or {}

    resource_type, resource_values = _nested_resource(
        resource
    )

    # ------------------------------------------------------------------
    # Column mask
    #
    # Current LLM extractor returns:
    #
    #   "columnMask": "'****'"
    #
    # while the resource contains:
    #
    #   "column": "salary"
    #
    # Convert it to the canonical:
    #
    #   "column_masks": {
    #       "salary": "'****'"
    #   }
    # ------------------------------------------------------------------



    column_masks: List[Dict[str, str]] = []
    row_filters: List[str] = []

    if has_mask:
        column_name = str(resource.get("column") or "").strip()
        mask_expression = str(column_mask or "").strip()

        if not column_name:
            raise ValueError(
                "A column mask requires a specific resource column."
            )

        if not mask_expression:
            raise ValueError(
                "A column mask requires a non-empty expression."
            )

        column_masks.append({
            "column": column_name,
            "expression": mask_expression,
        })

    if has_filter:
        table_name = str(resource.get("table") or "").strip()
        filter_expression = str(row_filter or "").strip()

        if not table_name:
            raise ValueError(
                "A row filter requires a specific table."
            )

        if not filter_expression:
            raise ValueError(
                "A row filter requires a non-empty expression."
            )

        row_filters.append(filter_expression)


    # ------------------------------------------------------------------
    # Final IR
    # ------------------------------------------------------------------

    return {
        "subject_attribute": "groups",
        "subject_value": _snake(group),

        "resource_type": resource_type,
        "resource_values": resource_values,

        "permissions": {
            "allow": allow,
            "deny": deny,
        },

        "column_masks": column_masks,
        "row_filters": row_filters,
    }