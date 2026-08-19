import tempfile
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional


# ============================================================
# Special OPA permissions
# ============================================================

FILTER_PERMISSION_MAPPING = {
    "GetColumnMask": "batchColumnMasks",
    "GetRowFilters": "rowFilters",
}


# ============================================================
# MAIN
# ============================================================

def build_permission_tree(
    opa_file: str,
    action_permissions_file: str,
    security_groups_file: str,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:

    opa_path = Path(opa_file)

    if not opa_path.exists():
        raise FileNotFoundError(
            f"OPA file not found: {opa_file}"
        )

    opa_text = opa_path.read_text(
        encoding="utf-8"
    )

    action_dependencies = _load_action_dependencies(
        action_permissions_file
    )

    security_groups = _load_security_groups(
        security_groups_file
    )

    # ========================================================
    # Parse explicit allow permissions
    # ========================================================

    rules = _extract_allow_rules(
        opa_text
    )

    _validate_rule_groups(
        rules,
        security_groups
    )

    groups: Dict[str, Dict[str, Any]] = {}

    for rule in rules:

        group = rule["group"]

        if group not in groups:
            groups[group] = _create_group()

        if rule.get("global_allow_all", False):
            groups[group]["global_allow_all"] = True

    # ========================================================
    # Parse filters
    # ========================================================

    filter_rules = _extract_filter_rules(
        opa_text
    )

    _validate_filter_groups(
        filter_rules,
        security_groups
    )

    # ========================================================
    # Process permissions
    # ========================================================

    for rule in rules:

        group = rule["group"]
        operation = rule["operation"]
        resource = rule["resource"]

        # A rule such as:
        #
        # allow if is_admin
        #
        # has no concrete permission.
        if operation is None:
            continue

        if resource["type"] == "global":

            _add_permission(
                groups[group],
                operation
            )

        elif resource["type"] == "catalog":

            catalog = _get_or_create_catalog(
                groups[group]["catalogs"],
                resource["catalog"]
            )

            _add_permission(
                catalog,
                operation
            )

        elif resource["type"] == "schema":

            catalog = _get_or_create_catalog(
                groups[group]["catalogs"],
                resource["catalog"]
            )

            schema = _get_or_create_schema(
                catalog["schemas"],
                resource["schema"]
            )

            _add_permission(
                schema,
                operation
            )

        elif resource["type"] == "table":

            catalog = _get_or_create_catalog(
                groups[group]["catalogs"],
                resource["catalog"]
            )

            schema = _get_or_create_schema(
                catalog["schemas"],
                resource["schema"]
            )

            table_name = resource.get("table")

            if table_name:

                table = _get_or_create_table(
                    schema.setdefault("tables", []),
                    table_name
                )

                _add_permission(
                    table,
                    operation
                )

            else:

                _add_permission(
                    schema,
                    operation
                )

    # ========================================================
    # Process filters
    # ========================================================

    for rule in filter_rules:

        group = rule["group"]

        if group.startswith("__not_"):

            excluded_group = _resolve_excluded_group(
                group
            )

            for security_group in security_groups:

                if security_group == excluded_group:
                    continue

                # Admin/unrestricted groups should not receive filters.
                if groups.get(
                        security_group,
                        {}
                ).get(
                    "global_allow_all",
                    False
                ):
                    continue

                expanded_rule = _deep_copy_json(
                    rule
                )

                expanded_rule["group"] = security_group

                _apply_filter_rule(
                    groups,
                    expanded_rule
                )

        elif group == "__global__":

            for security_group in security_groups:

                # Unrestricted groups bypass filters.
                if groups.get(
                        security_group,
                        {}
                ).get(
                    "global_allow_all",
                    False
                ):
                    continue

                expanded_rule = _deep_copy_json(
                    rule
                )

                expanded_rule["group"] = security_group

                _apply_filter_rule(
                    groups,
                    expanded_rule
                )

        else:

            # Explicit filters for an unrestricted group
            # are ignored because global access bypasses filters.
            if groups.get(
                    group,
                    {}
            ).get(
                "global_allow_all",
                False
            ):
                continue

            _apply_filter_rule(
                groups,
                rule
            )

    # ========================================================
    # Ensure all configured groups exist
    # ========================================================

    for security_group in security_groups:

        if security_group not in groups:

            groups[security_group] = _create_group()

    # ========================================================
    # Remove non-authoritative groups
    # ========================================================

    groups = {
        group: data
        for group, data in groups.items()
        if group in security_groups
    }

    # ========================================================
    # Calculate derived actions
    # ========================================================

    for group_data in groups.values():

        _calculate_allowed_actions(
            group_data,
            action_dependencies
        )

    # ========================================================
    # Remove internal fields
    # ========================================================

    _remove_internal_fields(
        groups
    )

    # ========================================================
    # Save
    # ========================================================

    if output_file is not None:

        output_path = Path(
            output_file
        )

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with output_path.open(
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                groups,
                f,
                indent=2,
                ensure_ascii=False
            )

    return groups


# ============================================================
# INTERNAL FIELD CLEANUP
# ============================================================

def _remove_internal_fields(
    groups: Dict[str, Dict[str, Any]],
) -> None:
    """
    Remove only fields that are genuinely internal.

    global_allow_all is intentionally preserved because it is
    required when permission trees are merged.
    """

    # Currently there are no additional internal fields to remove.
    pass


# ============================================================
# CREATE GROUP
# ============================================================

def _create_group() -> Dict[str, Any]:

    return {
        "permission": None,
        "filters": None,
        "catalogs": [],
        "global_allow_all": False,
    }


# ============================================================
# LOAD SECURITY GROUPS
# ============================================================

def _load_security_groups(
    security_groups_file: str,
) -> List[str]:

    path = Path(
        security_groups_file
    )

    if not path.exists():
        raise FileNotFoundError(
            f"Security groups file not found: "
            f"{security_groups_file}"
        )

    with path.open(
        "r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)

    if not isinstance(data, list):

        raise ValueError(
            "Security groups JSON must be a list."
        )

    groups = []

    for group in data:

        if not isinstance(group, str):

            raise ValueError(
                "Every security group must be a string."
            )

        group = group.strip()

        if not group:
            continue

        if group not in groups:

            groups.append(group)

    if not groups:

        raise ValueError(
            "Security groups JSON cannot be empty."
        )

    return groups


# ============================================================
# VALIDATE RULE GROUPS
# ============================================================

def _validate_rule_groups(
    rules: List[Dict[str, Any]],
    security_groups: List[str],
) -> None:

    allowed = set(
        security_groups
    )

    unknown_groups = sorted({
        rule["group"]
        for rule in rules
        if rule["group"] not in allowed
    })

    if unknown_groups:

        raise ValueError(
            "OPA policy contains unknown security groups: "
            f"{unknown_groups}. "
            f"Allowed groups are: {security_groups}"
        )


def _validate_filter_groups(
    rules: List[Dict[str, Any]],
    security_groups: List[str],
) -> None:

    allowed = set(
        security_groups
    )

    unknown_groups = sorted({
        rule["group"]
        for rule in rules
        if (
            rule.get("group") is not None
            and not rule["group"].startswith("__not_")
            and rule["group"] != "__global__"
            and rule["group"] not in allowed
        )
    })

    if unknown_groups:

        raise ValueError(
            "OPA filter rules contain unknown security "
            f"groups: {unknown_groups}. "
            f"Allowed groups are: {security_groups}"
        )


# ============================================================
# RESOLVE EXCLUDED GROUP
# ============================================================

def _resolve_excluded_group(
    synthetic_group: str,
) -> str:

    if synthetic_group == "__not_is_admin":
        return "admin"

    return synthetic_group[
        len("__not_") :
    ]


# ============================================================
# LOAD ACTION DEPENDENCIES
# ============================================================

def _load_action_dependencies(
    action_permissions_file: str,
) -> Dict[str, Any]:

    path = Path(
        action_permissions_file
    )

    if not path.exists():
        raise FileNotFoundError(
            f"Action permissions file not found: "
            f"{action_permissions_file}"
        )

    with path.open(
        "r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)

    if not isinstance(data, dict):

        raise ValueError(
            "Action permissions JSON must be an object."
        )

    return data


# ============================================================
# REGO ALLOW PARSER
# ============================================================
def _extract_allow_rules(
    opa_text: str,
) -> List[Dict[str, Any]]:

    helper_to_group = _extract_group_helpers(
        opa_text
    )

    rules: List[Dict[str, Any]] = []

    # ========================================================
    # DEBUG
    # ========================================================

    print("\n[DEBUG] Group helpers:")
    for helper, group in helper_to_group.items():
        print(f"    {helper} -> {group}")

    # ========================================================
    # BLOCK RULES
    #
    # allow if {
    #     is_admin
    # }
    #
    # allow if {
    #     is_finance_manager
    #     input.action.operation == "SelectFromColumns"
    # }
    # ========================================================

    for body in _extract_rule_bodies(
        opa_text,
        "allow"
    ):

        group = _resolve_group_from_body(
            body,
            helper_to_group
        )

        if group is None:
            continue

        # ----------------------------------------------------
        # Explicit operation
        # ----------------------------------------------------

        operation_match = re.search(
            r'input\.action\.operation\s*==\s*"([^"]+)"',
            body
        )

        if operation_match:

            operation = operation_match.group(1)

            resource = _extract_resource(
                body
            )

            rules.append({
                "group": group,
                "operation": operation,
                "resource": resource,
                "global_allow_all": False,
            })

            continue

        # ----------------------------------------------------
        # Operation set
        # ----------------------------------------------------

        operation_set_match = re.search(
            r'input\.action\.operation\s+in\s+'
            r'([A-Za-z_][A-Za-z0-9_]*)',
            body
        )

        if operation_set_match:

            operation_set_name = (
                operation_set_match.group(1)
            )

            operations = _extract_set_definition(
                opa_text,
                operation_set_name
            )

            resource = _extract_resource(
                body
            )

            for operation in operations:

                rules.append({
                    "group": group,
                    "operation": operation,
                    "resource": resource,
                    "global_allow_all": False,
                })

            continue

        # ----------------------------------------------------
        # NO OPERATION
        #
        # allow if {
        #     is_admin
        # }
        #
        # This means unrestricted global access.
        # ----------------------------------------------------

        print(
            f"[DEBUG] Global allow detected for group: {group}"
        )

        rules.append({
            "group": group,
            "operation": None,
            "resource": {
                "type": "global"
            },
            "global_allow_all": True,
        })

    # ========================================================
    # ONE-LINE RULES
    #
    # allow if is_admin
    # ========================================================

    one_line_pattern = re.compile(
        r'(?m)^\s*allow\s+if\s+'
        r'([A-Za-z_][A-Za-z0-9_]*)'
        r'\s*$'
    )

    for match in one_line_pattern.finditer(
        opa_text
    ):

        helper = match.group(1)

        group = helper_to_group.get(
            helper
        )

        if group is None:
            continue

        print(
            f"[DEBUG] One-line global allow detected: "
            f"{helper} -> {group}"
        )

        rules.append({
            "group": group,
            "operation": None,
            "resource": {
                "type": "global"
            },
            "global_allow_all": True,
        })

    # ========================================================
    # REMOVE DUPLICATES
    # ========================================================

    unique_rules = []
    seen = set()

    for rule in rules:

        key = json.dumps(
            rule,
            sort_keys=True
        )

        if key not in seen:

            seen.add(key)
            unique_rules.append(rule)

    return unique_rules


# ============================================================
# EXTRACT RULE BODIES
# ============================================================

def _extract_rule_bodies(
    opa_text: str,
    rule_name: str,
) -> List[str]:

    results = []

    pattern = re.compile(
        rf'\b{re.escape(rule_name)}\s+if\s*\{{'
    )

    for match in pattern.finditer(
        opa_text
    ):

        start = match.end() - 1

        body = _extract_balanced_block(
            opa_text,
            start
        )

        if body is not None:

            results.append(
                body
            )

    return results


def _extract_balanced_block(
    text: str,
    opening_brace_index: int,
) -> Optional[str]:

    depth = 0

    for i in range(
        opening_brace_index,
        len(text)
    ):

        char = text[i]

        if char == "{":
            depth += 1

        elif char == "}":

            depth -= 1

            if depth == 0:

                return text[
                    opening_brace_index + 1:i
                ]

    return None


# ============================================================
# GROUP HELPERS
# ============================================================

def _extract_group_helpers(
    opa_text: str,
) -> Dict[str, str]:

    result: Dict[str, str] = {}

    pattern = re.compile(
        r'(?m)^\s*'
        r'(?P<helper>[A-Za-z_][A-Za-z0-9_]*)'
        r'\s+if\s*\{'
    )

    for match in pattern.finditer(
        opa_text
    ):

        helper = match.group(
            "helper"
        )

        body = _extract_balanced_block(
            opa_text,
            match.end() - 1
        )

        if body is None:
            continue

        group_match = re.search(
            r'"([^"]+)"\s+in\s+'
            r'input\.context\.identity\.groups',
            body
        )

        if group_match:

            group = group_match.group(1)

            result[helper] = group

    return result



def _resolve_group_from_body(
    body: str,
    helper_to_group: Dict[str, str],
) -> Optional[str]:

    for helper, group in helper_to_group.items():

        if re.search(
            rf'\b{re.escape(helper)}\b',
            body
        ):

            return group

    return None


# ============================================================
# RESOURCE EXTRACTION
# ============================================================

def _extract_resource(
    body: str,
) -> Dict[str, Any]:

    table_catalog = _search_value(
        body,
        r'input\.action\.resource\.table\.catalogName'
    )

    table_schema = _search_value(
        body,
        r'input\.action\.resource\.table\.schemaName'
    )

    table_name = _search_value(
        body,
        r'input\.action\.resource\.table\.tableName'
    )

    if table_catalog:

        return {
            "type": "table",
            "catalog": table_catalog,
            "schema": table_schema,
            "table": table_name,
        }

    schema_catalog = _search_value(
        body,
        r'input\.action\.resource\.schema\.catalogName'
    )

    schema_name = _search_value(
        body,
        r'input\.action\.resource\.schema\.schemaName'
    )

    if schema_catalog:

        return {
            "type": "schema",
            "catalog": schema_catalog,
            "schema": schema_name,
        }

    catalog_name = _search_value(
        body,
        r'input\.action\.resource\.catalog\.'
        r'(?:name|catalogName)'
    )

    if catalog_name:

        return {
            "type": "catalog",
            "catalog": catalog_name,
        }

    return {
        "type": "global"
    }


def _search_value(
    body: str,
    field_pattern: str,
) -> Optional[str]:

    match = re.search(
        field_pattern +
        r'\s*==\s*"([^"]+)"',
        body
    )

    if match:

        return match.group(1)

    return None


# ============================================================
# SET DEFINITIONS
# ============================================================

def _extract_set_definition(
    opa_text: str,
    name: str,
) -> List[str]:

    pattern = re.compile(
        rf'{re.escape(name)}\s*:=\s*\{{'
        rf'(?P<body>.*?)'
        rf'\}}',
        re.DOTALL
    )

    match = pattern.search(
        opa_text
    )

    if not match:
        return []

    return re.findall(
        r'"([^"]+)"',
        match.group("body")
    )


# ============================================================
# FILTER PARSER
# ============================================================

def _extract_filter_rules(
    opa_text: str,
) -> List[Dict[str, Any]]:

    rules: List[Dict[str, Any]] = []

    helper_to_group = _extract_group_helpers(
        opa_text
    )

    # ========================================================
    # ROW FILTERS
    #
    # Supports:
    #
    # rowFilters contains row if {
    #     is_finance_manager
    #     ...
    # }
    # ========================================================

    row_pattern = re.compile(
        r'rowFilters\s+contains\s+'
        r'[A-Za-z_][A-Za-z0-9_]*\s+if\s*\{'
    )

    for match in row_pattern.finditer(
        opa_text
    ):

        body = _extract_balanced_block(
            opa_text,
            match.end() - 1
        )

        if body is None:
            continue

        group = _resolve_group_from_body(
            body,
            helper_to_group
        )

        if group is None:

            group = _resolve_filter_group(
                body
            )

        resource = _extract_filter_resource(
            body
        )

        expression = _extract_expression(
            body
        )

        if expression is None:
            continue

        rules.append({
            "group": group,
            "permission": "GetRowFilters",
            "resource": resource,
            "value": {
                "expression": expression
            },
            "type": "row",
        })

    # ========================================================
    # BATCH COLUMN MASKS
    # ========================================================

    for body in _extract_batch_mask_bodies(
        opa_text
    ):

        group = _resolve_group_from_body(
            body,
            helper_to_group
        )

        if group is None:

            group = _resolve_filter_group(
                body
            )

        resource = _extract_filter_resource(
            body
        )

        expression = _extract_expression(
            body
        )

        index = _extract_batch_index(
            body
        )

        if expression is None:
            continue

        rules.append({
            "group": group,
            "permission": "GetColumnMask",
            "resource": resource,
            "value": {
                "type": "batch",
                "index": index,
                "expression": expression,
            },
            "type": "batch",
        })

    # ========================================================
    # SINGLE COLUMN MASKS
    #
    # Supports:
    #
    # columnMask := {
    #     "expression": "..."
    # }
    #
    # and:
    #
    # columnMask := value if {
    #     ...
    # }
    # ========================================================

    for body in _extract_column_mask_bodies(
        opa_text
    ):

        group = _resolve_group_from_body(
            body,
            helper_to_group
        )

        if group is None:

            group = _resolve_filter_group(
                body
            )

        resource = _extract_column_resource(
            body
        )

        expression = _extract_expression(
            body
        )

        if expression is None:
            continue

        rules.append({
            "group": group,
            "permission": "GetColumnMask",
            "resource": resource,
            "value": {
                "type": "column",
                "expression": expression,
            },
            "type": "column",
        })

    return rules


# ============================================================
# BATCH MASK BODY EXTRACTION
# ============================================================

def _extract_batch_mask_bodies(
    opa_text: str,
) -> List[str]:

    results = []

    pattern = re.compile(
        r'batchColumnMasks\s+contains\s+'
        r'[A-Za-z_][A-Za-z0-9_]*\s+if\s*\{'
    )

    for match in pattern.finditer(
        opa_text
    ):

        body = _extract_balanced_block(
            opa_text,
            match.end() - 1
        )

        if body is not None:

            results.append(
                body
            )

    return results


# ============================================================
# COLUMN MASK BODY EXTRACTION
# ============================================================

def _extract_column_mask_bodies(
    opa_text: str,
) -> List[str]:

    results = []

    # --------------------------------------------------------
    # columnMask := value if {
    # --------------------------------------------------------

    pattern = re.compile(
        r'columnMask\s*:=\s*'
        r'[A-Za-z_][A-Za-z0-9_]*\s+if\s*\{'
    )

    for match in pattern.finditer(
        opa_text
    ):

        body = _extract_balanced_block(
            opa_text,
            match.end() - 1
        )

        if body is not None:

            results.append(
                body
            )

    # --------------------------------------------------------
    # columnMask := {
    #
    # Do not treat the default empty value as a filter.
    # --------------------------------------------------------

    pattern = re.compile(
        r'(?m)^\s*columnMask\s*:=\s*\{'
    )

    for match in pattern.finditer(
        opa_text
    ):

        body = _extract_balanced_block(
            opa_text,
            match.end() - 1
        )

        if body is not None:

            results.append(
                body
            )

    return results


# ============================================================
# FILTER RESOURCE
# ============================================================

def _extract_filter_resource(
    body: str,
) -> Dict[str, Any]:

    catalog = _search_any_value(
        body,
        [
            r'column_resource\.catalogName',
            r'table_resource\.catalogName',
            r'input\.action\.resource\.table\.catalogName',
        ]
    )

    schema = _search_any_value(
        body,
        [
            r'column_resource\.schemaName',
            r'table_resource\.schemaName',
            r'input\.action\.resource\.table\.schemaName',
        ]
    )

    table = _search_any_value(
        body,
        [
            r'column_resource\.tableName',
            r'table_resource\.tableName',
            r'input\.action\.resource\.table\.tableName',
        ]
    )

    column = _search_any_value(
        body,
        [
            r'column_resource\.columnName',
            r'input\.action\.resource\.column\.columnName',
        ]
    )

    if column is not None:

        return {
            "type": "column",
            "catalog": catalog,
            "schema": schema,
            "table": table,
            "column": column,
        }

    if table is not None:

        return {
            "type": "table",
            "catalog": catalog,
            "schema": schema,
            "table": table,
        }

    if schema is not None:

        return {
            "type": "schema",
            "catalog": catalog,
            "schema": schema,
        }

    if catalog is not None:

        return {
            "type": "catalog",
            "catalog": catalog,
        }

    return {
        "type": "global"
    }


def _extract_column_resource(
    body: str,
) -> Dict[str, Any]:

    catalog = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.catalogName'
        ]
    )

    schema = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.schemaName'
        ]
    )

    table = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.tableName'
        ]
    )

    column = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.columnName'
        ]
    )

    return {
        "type": "column",
        "catalog": catalog,
        "schema": schema,
        "table": table,
        "column": column,
    }


def _search_any_value(
    body: str,
    patterns: List[str],
) -> Optional[str]:

    for pattern in patterns:

        value = _search_value(
            body,
            pattern
        )

        if value is not None:

            return value

    return None


# ============================================================
# FILTER GROUP RESOLUTION
# ============================================================

def _resolve_filter_group(
    body: str,
) -> str:

    negative_helpers = re.findall(
        r'\bnot\s+([A-Za-z_][A-Za-z0-9_]*)',
        body
    )

    if negative_helpers:

        return "__not_" + negative_helpers[0]

    return "__global__"


# ============================================================
# FILTER VALUES
# ============================================================

def _extract_expression(
    body: str,
) -> Optional[str]:

    match = re.search(
        r'"expression"\s*:\s*"((?:[^"\\]|\\.)*)"',
        body
    )

    if match:

        return match.group(1)

    return None


def _extract_batch_index(
    body: str,
) -> str:

    if re.search(
        r'"index"\s*:\s*i\b',
        body
    ):

        return "*"

    match = re.search(
        r'"index"\s*:\s*(\d+)',
        body
    )

    if match:

        return match.group(1)

    return "*"


# ============================================================
# APPLY FILTER
# ============================================================

def _apply_filter_rule(
    groups: Dict[str, Dict[str, Any]],
    rule: Dict[str, Any],
) -> None:

    group = rule["group"]

    if group not in groups:

        groups[group] = _create_group()

    resource = rule["resource"]
    permission = rule["permission"]
    value = rule["value"]

    if resource["type"] == "global":

        _add_filter(
            groups[group],
            permission,
            value
        )

        return

    catalog = _get_or_create_catalog(
        groups[group]["catalogs"],
        resource["catalog"]
    )

    if resource["type"] == "catalog":

        _add_filter(
            catalog,
            permission,
            value
        )

        return

    schema = _get_or_create_schema(
        catalog["schemas"],
        resource["schema"]
    )

    if resource["type"] == "schema":

        _add_filter(
            schema,
            permission,
            value
        )

        return

    table_name = resource.get(
        "table"
    )

    if table_name is None:
        table_name = "*"

    table = _get_or_create_table(
        schema.setdefault(
            "tables",
            []
        ),
        table_name
    )

    if resource["type"] == "table":

        _add_filter(
            table,
            permission,
            value
        )

        return

    column_name = resource.get(
        "column"
    )

    if column_name is None:
        column_name = "*"

    column = _get_or_create_column(
        table.setdefault(
            "columns",
            []
        ),
        column_name
    )

    _add_filter(
        column,
        permission,
        value
    )


# ============================================================
# ACTION CALCULATION
# ============================================================

def _calculate_allowed_actions(
    group_data: Dict[str, Any],
    action_dependencies: Dict[str, Any],
) -> None:

    global_permissions = _permissions_as_set(
        group_data.get("permission")
    )

    global_available = (
        global_permissions
        | _filter_permissions_as_set(
            group_data.get("filters")
        )
    )

    # ========================================================
    # GLOBAL UNRESTRICTED GROUP
    # ========================================================

    if group_data.get(
        "global_allow_all",
        False
    ):

        _calculate_all_actions_globally(
            group_data,
            action_dependencies
        )

    else:

        _calculate_actions_at_scope(
            group_data,
            global_available,
            action_dependencies,
            allow_child_specific=False
        )

    # ========================================================
    # CATALOGS
    # ========================================================

    for catalog in group_data.get(
        "catalogs",
        []
    ):

        catalog_available = (
            global_available
            | _permissions_as_set(
                catalog.get("permission")
            )
            | _filter_permissions_as_set(
                catalog.get("filters")
            )
        )

        _calculate_actions_at_scope(
            catalog,
            catalog_available,
            action_dependencies,
            allow_child_specific=False
        )

        # ====================================================
        # SCHEMAS
        # ====================================================

        for schema in catalog.get(
            "schemas",
            []
        ):

            schema_available = (
                catalog_available
                | _permissions_as_set(
                    schema.get("permission")
                )
                | _filter_permissions_as_set(
                    schema.get("filters")
                )
            )

            _calculate_actions_at_scope(
                schema,
                schema_available,
                action_dependencies,
                allow_child_specific=True
            )

            # =================================================
            # TABLES
            # =================================================

            for table in schema.get(
                "tables",
                []
            ):

                table_available = (
                    schema_available
                    | _permissions_as_set(
                        table.get("permission")
                    )
                    | _filter_permissions_as_set(
                        table.get("filters")
                    )
                )

                _calculate_actions_at_scope(
                    table,
                    table_available,
                    action_dependencies,
                    allow_child_specific=True
                )

                # =============================================
                # COLUMNS
                # =============================================

                for column in table.get(
                    "columns",
                    []
                ):

                    column_available = (
                        table_available
                        | _permissions_as_set(
                            column.get("permission")
                        )
                        | _filter_permissions_as_set(
                            column.get("filters")
                        )
                    )

                    _calculate_actions_at_scope(
                        column,
                        column_available,
                        action_dependencies,
                        allow_child_specific=True
                    )


# ============================================================
# ALL ACTIONS GLOBALLY
# ============================================================

def _calculate_all_actions_globally(
    group_data: Dict[str, Any],
    action_dependencies: Dict[str, Any],
) -> None:

    actions = {}

    for action_name, requirements in (
        action_dependencies.items()
    ):

        if not isinstance(
            requirements,
            list
        ):
            continue

        actions[action_name] = {
            "requires": requirements
        }

    if actions:

        group_data["action_allowed"] = actions


def _calculate_actions_at_scope(
    node: Dict[str, Any],
    available: set,
    action_dependencies: Dict[str, Any],
    allow_child_specific: bool,
) -> None:

    actions = {}

    for action_name, requirements in (
        action_dependencies.items()
    ):

        if not isinstance(
            requirements,
            list
        ):
            continue

        if not _requirements_satisfied(
            requirements,
            available
        ):
            continue

        if (
            not allow_child_specific
            and _has_scope_specific_permission(
                requirements
            )
        ):
            continue

        actions[action_name] = {
            "requires": requirements
        }

    if actions:

        node["action_allowed"] = actions


# ============================================================
# PERMISSION HELPERS
# ============================================================

def _permissions_as_set(
    permissions: Optional[List[str]],
) -> set:

    if not permissions:
        return set()

    return set(
        permissions
    )


def _filter_permissions_as_set(
    filters: Optional[Dict[str, Any]],
) -> set:

    if not filters:
        return set()

    return set(
        filters.keys()
    )


def _requirements_satisfied(
    requirements: List[str],
    available: set,
) -> bool:

    return all(
        requirement in available
        for requirement in requirements
    )


# ============================================================
# CHILD-SCOPE PERMISSIONS
# ============================================================

def _has_scope_specific_permission(
    requirements: List[str],
) -> bool:

    scope_specific = {
        "SelectFromColumns",
        "UpdateTableColumns",
        "DeleteFromTable",
        "InsertIntoTable",
        "DropTable",
        "DropView",
        "CreateView",
        "CreateTable",
        "ShowColumns",
        "ShowTables",
    }

    return bool(
        set(requirements)
        & scope_specific
    )


# ============================================================
# TREE HELPERS
# ============================================================

def _get_or_create_catalog(
    catalogs: List[Dict[str, Any]],
    catalog_name: str,
) -> Dict[str, Any]:

    for catalog in catalogs:

        if catalog["catalog"] == catalog_name:

            return catalog

    catalog = {
        "catalog": catalog_name,
        "permission": None,
        "filters": None,
        "schemas": [],
    }

    catalogs.append(
        catalog
    )

    return catalog


def _get_or_create_schema(
    schemas: List[Dict[str, Any]],
    schema_name: str,
) -> Dict[str, Any]:

    for schema in schemas:

        if schema["schema"] == schema_name:

            return schema

    schema = {
        "schema": schema_name,
        "permission": None,
        "filters": None,
        "tables": [],
    }

    schemas.append(
        schema
    )

    return schema


def _get_or_create_table(
    tables: List[Dict[str, Any]],
    table_name: str,
) -> Dict[str, Any]:

    for table in tables:

        if table["table"] == table_name:

            return table

    table = {
        "table": table_name,
        "permission": None,
        "filters": None,
        "columns": [],
    }

    tables.append(
        table
    )

    return table


def _get_or_create_column(
    columns: List[Dict[str, Any]],
    column_name: str,
) -> Dict[str, Any]:

    for column in columns:

        if column["column"] == column_name:

            return column

    column = {
        "column": column_name,
        "permission": None,
        "filters": None,
    }

    columns.append(
        column
    )

    return column


# ============================================================
# PERMISSION
# ============================================================

def _add_permission(
    node: Dict[str, Any],
    permission: str,
) -> None:

    if node.get("permission") is None:

        node["permission"] = []

    _add_unique(
        node["permission"],
        permission
    )


# ============================================================
# FILTER
# ============================================================

def _add_filter(
    node: Dict[str, Any],
    filter_permission: str,
    value: Any,
) -> None:

    if node.get("filters") is None:

        node["filters"] = {}

    if filter_permission not in node["filters"]:

        node["filters"][filter_permission] = []

    existing = node["filters"][
        filter_permission
    ]

    if isinstance(existing, list):

        if value not in existing:

            existing.append(
                value
            )

    else:

        node["filters"][
            filter_permission
        ] = [value]


# ============================================================
# UNIQUE
# ============================================================

def _add_unique(
    values: List[str],
    value: str,
) -> None:

    if value not in values:

        values.append(
            value
        )




# ============================================================
# CLEAR DERIVED ACTIONS
# ============================================================

def _clear_derived_actions(
    group_data: Dict[str, Any],
) -> None:

    group_data.pop(
        "action_allowed",
        None
    )

    for catalog in group_data.get(
        "catalogs",
        []
    ):

        catalog.pop(
            "action_allowed",
            None
        )

        for schema in catalog.get(
            "schemas",
            []
        ):

            schema.pop(
                "action_allowed",
                None
            )

            for table in schema.get(
                "tables",
                []
            ):

                table.pop(
                    "action_allowed",
                    None
                )

                for column in table.get(
                    "columns",
                    []
                ):

                    column.pop(
                        "action_allowed",
                        None
                    )


# ============================================================
# MERGE
# ============================================================

def _merge_permission_trees(
    target: Dict[str, Any],
    source: Dict[str, Any],
) -> None:

    for group, source_group in source.items():

        if group not in target:

            target[group] = _deep_copy_json(
                source_group
            )

            continue

        target_group = target[group]

        # Ensure required structure exists.
        target_group.setdefault(
            "catalogs",
            []
        )

        # ----------------------------------------------------
        # Preserve unrestricted access.
        # ----------------------------------------------------

        if source_group.get(
            "global_allow_all",
            False
        ):

            target_group[
                "global_allow_all"
            ] = True

        # ----------------------------------------------------
        # Permissions
        # ----------------------------------------------------

        _merge_permission_value(
            target_group,
            source_group,
            "permission"
        )

        # ----------------------------------------------------
        # Filters
        # ----------------------------------------------------

        _merge_filter_value(
            target_group,
            source_group
        )

        # ----------------------------------------------------
        # Catalogs
        # ----------------------------------------------------

        for source_catalog in source_group.get(
            "catalogs",
            []
        ):

            target_catalog = _get_or_create_catalog(
                target_group["catalogs"],
                source_catalog["catalog"]
            )

            _merge_permission_value(
                target_catalog,
                source_catalog,
                "permission"
            )

            _merge_filter_value(
                target_catalog,
                source_catalog
            )

            # ------------------------------------------------
            # Schemas
            # ------------------------------------------------

            for source_schema in source_catalog.get(
                "schemas",
                []
            ):

                target_schema = _get_or_create_schema(
                    target_catalog["schemas"],
                    source_schema["schema"]
                )

                _merge_permission_value(
                    target_schema,
                    source_schema,
                    "permission"
                )

                _merge_filter_value(
                    target_schema,
                    source_schema
                )

                # --------------------------------------------
                # Tables
                # --------------------------------------------

                for source_table in source_schema.get(
                    "tables",
                    []
                ):

                    target_table = _get_or_create_table(
                        target_schema["tables"],
                        source_table["table"]
                    )

                    _merge_permission_value(
                        target_table,
                        source_table,
                        "permission"
                    )

                    _merge_filter_value(
                        target_table,
                        source_table
                    )

                    # ----------------------------------------
                    # Columns
                    # ----------------------------------------

                    for source_column in source_table.get(
                        "columns",
                        []
                    ):

                        target_column = _get_or_create_column(
                            target_table["columns"],
                            source_column["column"]
                        )

                        _merge_permission_value(
                            target_column,
                            source_column,
                            "permission"
                        )

                        _merge_filter_value(
                            target_column,
                            source_column
                        )


# ============================================================
# MERGE PERMISSION
# ============================================================

def _merge_permission_value(
    target: Dict[str, Any],
    source: Dict[str, Any],
    key: str,
) -> None:

    source_value = source.get(
        key
    )

    target_value = target.get(
        key
    )

    if source_value is None:
        return

    if target_value is None:

        target[key] = list(
            source_value
        )

        return

    for permission in source_value:

        _add_unique(
            target_value,
            permission
        )


# ============================================================
# MERGE FILTERS
# ============================================================

def _merge_filter_value(
    target: Dict[str, Any],
    source: Dict[str, Any],
) -> None:

    source_filters = source.get(
        "filters"
    )

    if source_filters is None:
        return

    target_filters = target.get(
        "filters"
    )

    if target_filters is None:

        target["filters"] = _deep_copy_json(
            source_filters
        )

        return

    for filter_name, source_values in (
        source_filters.items()
    ):

        if filter_name not in target_filters:

            target_filters[
                filter_name
            ] = _deep_copy_json(
                source_values
            )

            continue

        target_values = target_filters[
            filter_name
        ]

        if not isinstance(
            target_values,
            list
        ):

            target_values = [
                target_values
            ]

            target_filters[
                filter_name
            ] = target_values

        if isinstance(
            source_values,
            list
        ):

            for value in source_values:

                if value not in target_values:

                    target_values.append(
                        _deep_copy_json(
                            value
                        )
                    )


# ============================================================
# COPY
# ============================================================

def _deep_copy_json(
    value: Any,
) -> Any:

    return json.loads(
        json.dumps(value)
    )


def _combine_rego_files(
    opa_directory: str,
) -> Path:
    """
    Combine all .rego files in a directory into one temporary file.

    The temporary file is created explicitly and must be deleted by
    the caller.
    """

    opa_dir = Path(opa_directory)

    if not opa_dir.exists():
        raise FileNotFoundError(
            f"OPA directory not found: {opa_directory}"
        )

    if not opa_dir.is_dir():
        raise NotADirectoryError(
            f"OPA path is not a directory: {opa_directory}"
        )

    opa_files = sorted(
        opa_dir.glob("*.rego")
    )

    if not opa_files:
        raise FileNotFoundError(
            f"No .rego files found in: {opa_directory}"
        )

    # --------------------------------------------------------
    # Create temporary file
    # --------------------------------------------------------

    temporary_file = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".rego",
        prefix="combined_opa_",
        delete=False,
    )

    temporary_path = Path(
        temporary_file.name
    )

    try:

        for opa_file in opa_files:

            print(
                f"[COMBINE] Adding: {opa_file.name}"
            )

            content = opa_file.read_text(
                encoding="utf-8"
            )

            temporary_file.write(
                f"\n\n# ============================================================\n"
            )

            temporary_file.write(
                f"# FILE: {opa_file.name}\n"
            )

            temporary_file.write(
                f"# ============================================================\n\n"
            )

            temporary_file.write(
                content
            )

            temporary_file.write(
                "\n\n"
            )

    except Exception:

        temporary_file.close()

        temporary_path.unlink(
            missing_ok=True
        )

        raise

    finally:

        if not temporary_file.closed:
            temporary_file.close()

    print(
        f"[COMBINE] Created temporary Rego file: "
        f"{temporary_path}"
    )

    return temporary_path


# ============================================================
# DIRECTORY VERSION
# ============================================================


def build_permission_tree_from_directory(
    opa_directory: str,
    action_permissions_file: str,
    security_groups_file: str,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a permission tree from all .rego files in a directory.

    All .rego files are combined into a temporary Rego file and
    processed together.

    The temporary file is always deleted.
    """

    temporary_rego: Optional[Path] = None

    try:

        temporary_rego = _combine_rego_files(
            opa_directory
        )

        print(
            f"[BUILD] Parsing combined policy: "
            f"{temporary_rego}"
        )

        actual_tree = build_permission_tree(
            opa_file=str(
                temporary_rego
            ),
            action_permissions_file=action_permissions_file,
            security_groups_file=security_groups_file,
            output_file=output_file,
        )

        return actual_tree

    finally:

        if temporary_rego is not None:

            temporary_rego.unlink(
                missing_ok=True
            )

            print(
                f"[CLEANUP] Removed temporary file: "
                f"{temporary_rego}"
            )



# ============================================================
# EXAMPLE
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

OPA_DIRECTORY = (
    PROJECT_ROOT
    / "docker-compose"
    / "opa"
)

ACTION_PERMISSIONS_FILE = (
    PROJECT_ROOT
    / "LLM"
    / "Structure"
    / "checkForAction.json"
)

SECURITY_GROUPS_FILE = (
    PROJECT_ROOT
    / "LLM"
    / "Structure"
    / "security_groups.json"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "TreePermission"
    / "output"
    / "permission_tree.json"
)


if __name__ == "__main__":

    print("=" * 70)
    print("BUILDING PERMISSION TREE")
    print("=" * 70)

    print(
        f"Project root:       {PROJECT_ROOT}"
    )

    print(
        f"OPA directory:      {OPA_DIRECTORY}"
    )

    print(
        f"Action permissions: {ACTION_PERMISSIONS_FILE}"
    )

    print(
        f"Security groups:    {SECURITY_GROUPS_FILE}"
    )

    print(
        f"Output:             {OUTPUT_FILE}"
    )

    tree = build_permission_tree_from_directory(
        opa_directory=str(
            OPA_DIRECTORY
        ),
        action_permissions_file=str(
            ACTION_PERMISSIONS_FILE
        ),
        security_groups_file=str(
            SECURITY_GROUPS_FILE
        ),
        output_file=str(
            OUTPUT_FILE
        ),
    )

    print("\nPermission tree:")

    print(
        json.dumps(
            tree,
            indent=2,
            ensure_ascii=False
        )
    )