import tempfile
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

FILTER_PERMISSION_MAPPING = {
    "GetColumnMask": "batchColumnMasks",
    "GetRowFilters": "rowFilters",
}


def build_permission_tree(opa_file: str, action_permissions_file: str, security_groups_file: str, output_file: Optional[str] = None) -> Dict[str, Any]:
    opa_path = Path(opa_file)

    if not opa_path.exists():
        raise FileNotFoundError(f"OPA file not found: {opa_file}")

    opa_text = opa_path.read_text(encoding="utf-8")
    action_dependencies = _load_action_dependencies(action_permissions_file)
    security_groups = _load_security_groups(security_groups_file)

    rules = _extract_allow_rules(opa_text)
    _validate_rule_groups(rules, security_groups)

    groups: Dict[str, Dict[str, Any]] = {}

    for rule in rules:
        group = rule["group"]

        if group not in groups:
            groups[group] = _create_group()

        if rule.get("global_allow_all", False):
            groups[group]["global_allow_all"] = True

    filter_rules = _extract_filter_rules(opa_text)
    _validate_filter_groups(filter_rules, security_groups)

    for rule in rules:
        _apply_resource_permission(groups, rule)

    for rule in filter_rules:
        group = rule["group"]

        if group.startswith("__not_"):
            excluded_group = _resolve_excluded_group(group)

            for security_group in security_groups:
                if security_group == excluded_group:
                    continue

                if groups.get(security_group, {}).get("global_allow_all", False):
                    continue

                expanded_rule = _deep_copy_json(rule)
                expanded_rule["group"] = security_group
                _apply_filter_rule(groups, expanded_rule)

        elif group == "__global__":
            for security_group in security_groups:
                if groups.get(security_group, {}).get("global_allow_all", False):
                    continue

                expanded_rule = _deep_copy_json(rule)
                expanded_rule["group"] = security_group
                _apply_filter_rule(groups, expanded_rule)

        else:
            if groups.get(group, {}).get("global_allow_all", False):
                continue

            _apply_filter_rule(groups, rule)

    for security_group in security_groups:
        if security_group not in groups:
            groups[security_group] = _create_group()

    groups = {
        group: data
        for group, data in groups.items()
        if group in security_groups
    }

    permission_tree = _build_resource_permission_tree(groups, action_dependencies)

    if output_file is not None:
        _write_permission_tree(permission_tree, output_file)

    return permission_tree


def _write_permission_tree(permission_tree: Dict[str, Any], output_file: str) -> None:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(permission_tree, f, indent=2, ensure_ascii=False)


def _create_group() -> Dict[str, Any]:
    return {
        "permissions": None,
        "filters": None,
        "catalogs": [],
        "global_allow_all": False,
    }


def _load_security_groups(security_groups_file: str) -> List[str]:
    path = Path(security_groups_file)

    if not path.exists():
        raise FileNotFoundError(
            f"Security groups file not found: {security_groups_file}"
        )

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Security groups JSON must be a list.")

    groups = []

    for group in data:
        if not isinstance(group, str):
            raise ValueError("Every security group must be a string.")

        group = group.strip()

        if group and group not in groups:
            groups.append(group)

    if not groups:
        raise ValueError("Security groups JSON cannot be empty.")

    return groups


def _validate_rule_groups(
    rules: List[Dict[str, Any]],
    security_groups: List[str],
) -> None:
    allowed = set(security_groups)

    unknown_groups = sorted(
        {
            rule["group"]
            for rule in rules
            if rule["group"] not in allowed
        }
    )

    if unknown_groups:
        raise ValueError(
            f"OPA policy contains unknown security groups: "
            f"{unknown_groups}. Allowed groups are: {security_groups}"
        )


def _validate_filter_groups(
    rules: List[Dict[str, Any]],
    security_groups: List[str],
) -> None:
    allowed = set(security_groups)

    unknown_groups = sorted(
        {
            rule["group"]
            for rule in rules
            if rule.get("group") is not None
            and not rule["group"].startswith("__not_")
            and rule["group"] != "__global__"
            and rule["group"] not in allowed
        }
    )

    if unknown_groups:
        raise ValueError(
            f"OPA filter rules contain unknown security groups: "
            f"{unknown_groups}. Allowed groups are: {security_groups}"
        )


def _resolve_excluded_group(synthetic_group: str) -> str:
    if synthetic_group == "__not_is_admin":
        return "admin"

    return synthetic_group[len("__not_"):]


def _load_action_dependencies(action_permissions_file: str) -> Dict[str, Any]:
    path = Path(action_permissions_file)

    if not path.exists():
        raise FileNotFoundError(
            f"Action permissions file not found: {action_permissions_file}"
        )

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Action permissions JSON must be an object.")

    return data


def _extract_operation(body: str) -> Optional[str]:
    match = re.search(
        r'input\.action\.operation\s*==\s*"([^"]+)"',
        body,
    )

    return match.group(1) if match else None


def _extract_allow_rules(opa_text: str) -> List[Dict[str, Any]]:
    helper_to_group = _extract_group_helpers(opa_text)
    rules: List[Dict[str, Any]] = []

    print("\n[DEBUG] Group helpers:")

    for helper, group in helper_to_group.items():
        print(f"    {helper} -> {group}")

    for body in _extract_rule_bodies(opa_text, "allow"):
        group = _resolve_group_from_body(body, helper_to_group)

        if group is None:
            continue

        operation_match = re.search(
            r'input\.action\.operation\s*==\s*"([^"]+)"',
            body,
        )

        if operation_match:
            rules.append(
                {
                    "group": group,
                    "operation": operation_match.group(1),
                    "resource": _extract_resource(body),
                    "global_allow_all": False,
                }
            )
            continue

        operation_set_match = re.search(
            r'input\.action\.operation\s+in\s+([A-Za-z_][A-Za-z0-9_]*)',
            body,
        )

        if operation_set_match:
            operations = _extract_set_definition(
                opa_text,
                operation_set_match.group(1),
            )

            resource = _extract_resource(body)

            for operation in operations:
                rules.append(
                    {
                        "group": group,
                        "operation": operation,
                        "resource": resource,
                        "global_allow_all": False,
                    }
                )

            continue

        schema_in_match = re.search(
            r'input\.action\.resource\.schema\.schemaName\s+in\s*\{([^}]+)\}',
            body,
        )

        if schema_in_match:
            catalog = _search_value(
                body,
                r'input\.action\.resource\.schema\.catalogName',
            )

            if catalog:
                schema_names = re.findall(
                    r'"([^"]+)"',
                    schema_in_match.group(1),
                )

                operation = _extract_operation(body)

                if operation:
                    for schema_name in schema_names:
                        rules.append(
                            {
                                "group": group,
                                "operation": operation,
                                "resource": {
                                    "type": "schema",
                                    "catalog": catalog,
                                    "schema": schema_name,
                                },
                                "global_allow_all": False,
                            }
                        )

                    continue

        print(f"[DEBUG] Global allow detected for group: {group}")

        rules.append(
            {
                "group": group,
                "operation": None,
                "resource": {"type": "global"},
                "global_allow_all": True,
            }
        )

    one_line_pattern = re.compile(
        r'(?m)^\s*allow\s+if\s+([A-Za-z_][A-Za-z0-9_]+)\s*$'
    )

    for match in one_line_pattern.finditer(opa_text):
        helper = match.group(1)
        group = helper_to_group.get(helper)

        if group is None:
            continue

        print(
            f"[DEBUG] One-line global allow detected: "
            f"{helper} -> {group}"
        )

        rules.append(
            {
                "group": group,
                "operation": None,
                "resource": {"type": "global"},
                "global_allow_all": True,
            }
        )

    unique_rules = []
    seen = set()

    for rule in rules:
        key = json.dumps(rule, sort_keys=True)

        if key not in seen:
            seen.add(key)
            unique_rules.append(rule)

    return unique_rules



def _extract_rule_bodies(opa_text: str, rule_name: str) -> List[str]:
    results = []

    pattern = re.compile(
        rf'\b{re.escape(rule_name)}\s+if\s*\{{'
    )

    for match in pattern.finditer(opa_text):
        body = _extract_balanced_block(
            opa_text,
            match.end() - 1,
        )

        if body is not None:
            results.append(body)

    return results

def _extract_balanced_block(
    text: str,
    opening_brace_index: int,
) -> Optional[str]:
    depth = 0

    for i in range(opening_brace_index, len(text)):
        char = text[i]

        if char == "{":
            depth += 1

        elif char == "}":
            depth -= 1

            if depth == 0:
                return text[opening_brace_index + 1:i]

    return None


def _extract_group_helpers(opa_text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}

    pattern = re.compile(
        r'(?m)^\s*(?P<helper>[A-Za-z_][A-Za-z0-9_]*)\s+if\s*\{'
    )

    for match in pattern.finditer(opa_text):
        helper = match.group("helper")

        body = _extract_balanced_block(
            opa_text,
            match.end() - 1,
        )

        if body is None:
            continue

        group_match = re.search(
            r'"([^"]+)"\s+in\s+input\.context\.identity\.groups',
            body,
        )

        if group_match:
            result[helper] = group_match.group(1)

    return result


def _resolve_group_from_body(
    body: str,
    helper_to_group: Dict[str, str],
) -> Optional[str]:
    negative_helpers = re.findall(
        r'\bnot\s+([A-Za-z_][A-Za-z0-9_]*)',
        body,
    )

    if negative_helpers:
        helper = negative_helpers[0]
        return "__not_" + helper

    for helper, group in helper_to_group.items():
        if re.search(
            rf'\b{re.escape(helper)}\b',
            body,
        ):
            return group

    return None


def _extract_resource(body: str) -> Dict[str, Any]:
    table_catalog = _search_value(
        body,
        r'input\.action\.resource\.table\.catalogName',
    )

    table_schema = _search_value(
        body,
        r'input\.action\.resource\.table\.schemaName',
    )

    table_name = _search_value(
        body,
        r'input\.action\.resource\.table\.tableName',
    )

    if table_catalog and table_schema:
        return {
            "type": "table",
            "catalog": table_catalog,
            "schema": table_schema,
            "table": table_name,
        }

    schema_catalog = _search_value(
        body,
        r'input\.action\.resource\.schema\.catalogName',
    )

    schema_name = _search_value(
        body,
        r'input\.action\.resource\.schema\.schemaName',
    )

    if schema_catalog and schema_name:
        return {
            "type": "schema",
            "catalog": schema_catalog,
            "schema": schema_name,
        }

    catalog_name = _search_value(
        body,
        r'input\.action\.resource\.catalog\.(?:name|catalogName)',
    )

    if catalog_name:
        return {
            "type": "catalog",
            "catalog": catalog_name,
        }

    return {"type": "global"}


def _search_value(
    body: str,
    field_pattern: str,
) -> Optional[str]:
    match = re.search(
        field_pattern + r'\s*==\s*"([^"]+)"',
        body,
    )

    return match.group(1) if match else None


def _extract_set_definition(
    opa_text: str,
    name: str,
) -> List[str]:
    pattern = re.compile(
        rf'{re.escape(name)}\s*:=\s*\{{(?P<body>.*?)\}}',
        re.DOTALL,
    )

    match = pattern.search(opa_text)

    if not match:
        return []

    return re.findall(
        r'"([^"]+)"',
        match.group("body"),
    )


def _apply_resource_permission(
    groups: Dict[str, Dict[str, Any]],
    rule: Dict[str, Any],
) -> None:
    group = rule["group"]
    operation = rule["operation"]
    resource = rule["resource"]

    if operation is None:
        return

    if group not in groups:
        groups[group] = _create_group()

    if resource["type"] == "global":
        _add_permission(
            groups[group],
            operation,
        )
        return

    catalog_name = resource.get("catalog")

    if not catalog_name:
        return

    catalog = _get_or_create_catalog(
        groups[group]["catalogs"],
        catalog_name,
    )

    if resource["type"] == "catalog":
        _add_permission(
            catalog,
            operation,
        )
        return

    schema_name = resource.get("schema")

    if not schema_name:
        return

    schema = _get_or_create_schema(
        catalog["schemas"],
        schema_name,
    )

    if resource["type"] == "schema":
        _add_permission(
            schema,
            operation,
        )
        return

    table_name = resource.get("table")

    if table_name:
        table = _get_or_create_table(
            schema.setdefault("tables", []),
            table_name,
        )

        _add_permission(
            table,
            operation,
        )
    else:
        _add_permission(
            schema,
            operation,
        )


def _extract_filter_rules(
    opa_text: str,
) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []

    helper_to_group = _extract_group_helpers(opa_text)

    for body in _extract_row_filter_bodies(opa_text):
        group = _resolve_filter_group_from_body(
            body,
            helper_to_group,
        )

        resource = _extract_filter_resource(body)
        expression = _extract_expression(body)

        if expression is None:
            continue

        rules.append(
            {
                "group": group,
                "permissions": "GetRowFilters",
                "resource": resource,
                "value": {
                    "expression": expression,
                },
                "type": "row",
            }
        )

    for body in _extract_batch_mask_bodies(opa_text):
        group = _resolve_filter_group_from_body(
            body,
            helper_to_group,
        )

        resource = _extract_filter_resource(body)
        expression = _extract_expression(body)
        index = _extract_batch_index(body)

        if expression is None:
            continue

        rules.append(
            {
                "group": group,
                "permissions": "GetColumnMask",
                "resource": resource,
                "value": {
                    "type": "batch",
                    "index": index,
                    "expression": expression,
                },
                "type": "batch",
            }
        )

    for body in _extract_column_mask_bodies(opa_text):
        group = _resolve_filter_group_from_body(
            body,
            helper_to_group,
        )

        resource = _extract_column_resource(body)
        expression = _extract_expression(body)

        if expression is None:
            continue

        rules.append(
            {
                "group": group,
                "permissions": "GetColumnMask",
                "resource": resource,
                "value": {
                    "type": "column",
                    "expression": expression,
                },
                "type": "column",
            }
        )

    return rules


def _resolve_filter_group_from_body(
    body: str,
    helper_to_group: Dict[str, str],
) -> str:
    negative_helpers = re.findall(
        r'\bnot\s+([A-Za-z_][A-Za-z0-9_]*)',
        body,
    )

    if negative_helpers:
        return "__not_" + negative_helpers[0]

    for helper, group in helper_to_group.items():
        if re.search(
            rf'\b{re.escape(helper)}\b',
            body,
        ):
            return group

    return "__global__"


def _extract_row_filter_bodies(
    opa_text: str,
) -> List[str]:
    results = []

    patterns = [
        re.compile(
            r'rowFilters\s+contains\s+'
            r'(?:[A-Za-z_][A-Za-z0-9_]*|\{[^\n]*\})'
            r'\s+if\s*\{'
        ),
        re.compile(
            r'rowFilters\s*:=\s*'
            r'[A-Za-z_][A-Za-z0-9_]*\s+if\s*\{'
        ),
    ]

    for pattern in patterns:
        for match in pattern.finditer(opa_text):
            body = _extract_balanced_block(
                opa_text,
                match.end() - 1,
            )

            if body is not None:
                results.append(body)

    return results


def _extract_batch_mask_bodies(
    opa_text: str,
) -> List[str]:
    results = []

    pattern = re.compile(
        r'batchColumnMasks\s+contains\s+'
        r'[A-Za-z_][A-Za-z0-9_]*\s+if\s*\{'
    )

    for match in pattern.finditer(opa_text):
        body = _extract_balanced_block(
            opa_text,
            match.end() - 1,
        )

        if body is not None:
            results.append(body)

    return results


def _extract_column_mask_bodies(
    opa_text: str,
) -> List[str]:
    results = []

    pattern = re.compile(
        r'(?m)^\s*columnMask\s*:=\s*'
        r'(?:\{[^\n]*\}|[A-Za-z_][A-Za-z0-9_]*)'
        r'\s+if\s*\{'
    )

    for match in pattern.finditer(opa_text):
        body = _extract_balanced_block(
            opa_text,
            match.end() - 1,
        )

        if body is not None:
            results.append(body)

    return results


def _resolve_filter_aliases(body: str) -> str:
    aliases = {
        "table_resource": "input.action.resource.table",
        "column_resource": "input.action.resource.column",
    }

    for alias, target in aliases.items():
        body = re.sub(
            rf'\b{alias}\.',
            target + ".",
            body,
        )

    return body


def _extract_filter_resource(
    body: str,
) -> Dict[str, Any]:
    body = _resolve_filter_aliases(body)

    catalog = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.catalogName',
            r'input\.action\.resource\.table\.catalogName',
        ],
    )

    schema = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.schemaName',
            r'input\.action\.resource\.table\.schemaName',
        ],
    )

    table = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.tableName',
            r'input\.action\.resource\.table\.tableName',
        ],
    )

    column = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.columnName',
        ],
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

    return {"type": "global"}


def _extract_column_resource(
    body: str,
) -> Dict[str, Any]:
    body = _resolve_filter_aliases(body)

    catalog = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.catalogName',
        ],
    )

    schema = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.schemaName',
        ],
    )

    table = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.tableName',
        ],
    )

    column = _search_any_value(
        body,
        [
            r'input\.action\.resource\.column\.columnName',
        ],
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
            pattern,
        )

        if value is not None:
            return value

    return None


def _extract_expression(
    body: str,
) -> Optional[str]:
    pattern = r'"expression"\s*:\s*"((?:[^"\\]|\\.)*)"'

    match = re.search(
        pattern,
        body,
    )

    if match:
        return match.group(1)

    return None


def _extract_batch_index(body: str) -> str:
    if re.search(
        r'"index"\s*:\s*i\b',
        body,
    ):
        return "*"

    match = re.search(
        r'"index"\s*:\s*(\d+)',
        body,
    )

    if match:
        return match.group(1)

    return "*"


def _apply_filter_rule(
    groups: Dict[str, Dict[str, Any]],
    rule: Dict[str, Any],
) -> None:
    group = rule["group"]

    if group not in groups:
        groups[group] = _create_group()

    resource = rule["resource"]
    permission = rule["permissions"]
    value = rule["value"]

    if resource["type"] == "global":
        _add_filter(
            groups[group],
            permission,
            value,
        )
        return

    catalog_name = resource.get("catalog")

    if not catalog_name:
        return

    catalog = _get_or_create_catalog(
        groups[group]["catalogs"],
        catalog_name,
    )

    if resource["type"] == "catalog":
        _add_filter(
            catalog,
            permission,
            value,
        )
        return

    schema_name = resource.get("schema")

    if not schema_name:
        return

    schema = _get_or_create_schema(
        catalog["schemas"],
        schema_name,
    )

    if resource["type"] == "schema":
        _add_filter(
            schema,
            permission,
            value,
        )
        return

    table_name = resource.get("table")

    if not table_name:
        return

    table = _get_or_create_table(
        schema.setdefault("tables", []),
        table_name,
    )

    if resource["type"] == "table":
        _add_filter(
            table,
            permission,
            value,
        )
        return

    column_name = resource.get("column")

    if not column_name:
        return

    column = _get_or_create_column(
        table.setdefault("columns", []),
        column_name,
    )

    _add_filter(
        column,
        permission,
        value,
    )


def _build_resource_permission_tree(
    groups: Dict[str, Dict[str, Any]],
    action_dependencies: Dict[str, Any],
) -> Dict[str, Any]:
    tree: Dict[str, Any] = {
        "ROOT": {
            "security_groups": {},
        }
    }

    root = tree["ROOT"]

    for group_name, group_data in groups.items():
        local = _build_local_security_group_entry(
            group_data
        )

        if group_data.get("global_allow_all", False):
            local["permissions"] = ["*"]

        root["security_groups"][group_name] = local

    catalog_names = set()

    for group_data in groups.values():
        for catalog in group_data.get("catalogs", []):
            catalog_name = catalog.get("catalog")

            if catalog_name:
                catalog_names.add(catalog_name)

    for catalog_name in sorted(catalog_names):
        catalog_node = {
            "security_groups": {},
            "schemas": {},
        }

        root.setdefault(
            "catalogs",
            {}
        )[catalog_name] = catalog_node

        for group_name, group_data in groups.items():
            catalog = _find_named_node(
                group_data.get("catalogs", []),
                "catalog",
                catalog_name,
            )

            if catalog is not None:
                _merge_local_resource_entry(
                    catalog_node,
                    group_name,
                    catalog,
                )

        schema_names = set()

        for group_data in groups.values():
            catalog = _find_named_node(
                group_data.get("catalogs", []),
                "catalog",
                catalog_name,
            )

            if catalog is None:
                continue

            for schema in catalog.get("schemas", []):
                schema_name = schema.get("schema")

                if schema_name:
                    schema_names.add(schema_name)

        for schema_name in sorted(schema_names):
            schema_node = {
                "security_groups": {},
                "tables": {},
            }

            catalog_node["schemas"][schema_name] = schema_node

            for group_name, group_data in groups.items():
                catalog = _find_named_node(
                    group_data.get("catalogs", []),
                    "catalog",
                    catalog_name,
                )

                if catalog is None:
                    continue

                schema = _find_named_node(
                    catalog.get("schemas", []),
                    "schema",
                    schema_name,
                )

                if schema is not None:
                    _merge_local_resource_entry(
                        schema_node,
                        group_name,
                        schema,
                    )

            table_names = set()

            for group_data in groups.values():
                catalog = _find_named_node(
                    group_data.get("catalogs", []),
                    "catalog",
                    catalog_name,
                )

                if catalog is None:
                    continue

                schema = _find_named_node(
                    catalog.get("schemas", []),
                    "schema",
                    schema_name,
                )

                if schema is None:
                    continue

                for table in schema.get("tables", []):
                    table_name = table.get("table")

                    if table_name:
                        table_names.add(table_name)

            for table_name in sorted(table_names):
                table_node = {
                    "security_groups": {},
                    "columns": {},
                }

                schema_node["tables"][table_name] = table_node

                for group_name, group_data in groups.items():
                    catalog = _find_named_node(
                        group_data.get("catalogs", []),
                        "catalog",
                        catalog_name,
                    )

                    if catalog is None:
                        continue

                    schema = _find_named_node(
                        catalog.get("schemas", []),
                        "schema",
                        schema_name,
                    )

                    if schema is None:
                        continue

                    table = _find_named_node(
                        schema.get("tables", []),
                        "table",
                        table_name,
                    )

                    if table is not None:
                        _merge_local_resource_entry(
                            table_node,
                            group_name,
                            table,
                        )

                column_names = set()

                for group_data in groups.values():
                    catalog = _find_named_node(
                        group_data.get("catalogs", []),
                        "catalog",
                        catalog_name,
                    )

                    if catalog is None:
                        continue

                    schema = _find_named_node(
                        catalog.get("schemas", []),
                        "schema",
                        schema_name,
                    )

                    if schema is None:
                        continue

                    table = _find_named_node(
                        schema.get("tables", []),
                        "table",
                        table_name,
                    )

                    if table is None:
                        continue

                    for column in table.get("columns", []):
                        column_name = column.get("column")

                        if column_name:
                            column_names.add(column_name)

                for column_name in sorted(column_names):
                    column_node = {
                        "security_groups": {},
                    }

                    table_node["columns"][column_name] = column_node

                    for group_name, group_data in groups.items():
                        catalog = _find_named_node(
                            group_data.get("catalogs", []),
                            "catalog",
                            catalog_name,
                        )

                        if catalog is None:
                            continue

                        schema = _find_named_node(
                            catalog.get("schemas", []),
                            "schema",
                            schema_name,
                        )

                        if schema is None:
                            continue

                        table = _find_named_node(
                            schema.get("tables", []),
                            "table",
                            table_name,
                        )

                        if table is None:
                            continue

                        column = _find_named_node(
                            table.get("columns", []),
                            "column",
                            column_name,
                        )

                        if column is not None:
                            _merge_local_resource_entry(
                                column_node,
                                group_name,
                                column,
                            )

    _calculate_tree_allowed_actions(
        tree["ROOT"],
        action_dependencies,
    )

    _prune_empty_tree_nodes(tree["ROOT"])

    return tree


def _build_local_security_group_entry(
    group_data: Dict[str, Any],
) -> Dict[str, Any]:
    entry: Dict[str, Any] = {}

    if group_data.get("permissions"):
        entry["permissions"] = list(
            group_data["permissions"]
        )

    if group_data.get("filters"):
        entry["filters"] = _deep_copy_json(
            group_data["filters"]
        )

    return entry


def _merge_local_resource_entry(
    resource_node: Dict[str, Any],
    group_name: str,
    source_node: Dict[str, Any],
) -> None:
    entry = _build_local_security_group_entry(
        source_node
    )

    if entry:
        resource_node.setdefault(
            "security_groups",
            {}
        )[group_name] = entry


def _find_named_node(
    nodes: List[Dict[str, Any]],
    key: str,
    value: str,
) -> Optional[Dict[str, Any]]:
    for node in nodes:
        if node.get(key) == value:
            return node

    return None


def _calculate_tree_allowed_actions(
    root: Dict[str, Any],
    action_dependencies: Dict[str, Any],
) -> None:
    for group_name in sorted(
        _collect_tree_groups(root)
    ):
        _calculate_group_tree_delta(
            root,
            group_name,
            action_dependencies,
        )


def _collect_tree_groups(
    root: Dict[str, Any],
) -> set:
    groups = set(
        root.get("security_groups", {}).keys()
    )

    for catalog in root.get(
        "catalogs",
        {}
    ).values():
        groups.update(
            catalog.get(
                "security_groups",
                {}
            ).keys()
        )

        for schema in catalog.get(
            "schemas",
            {}
        ).values():
            groups.update(
                schema.get(
                    "security_groups",
                    {}
                ).keys()
            )

            for table in schema.get(
                "tables",
                {}
            ).values():
                groups.update(
                    table.get(
                        "security_groups",
                        {}
                    ).keys()
                )

                for column in table.get(
                    "columns",
                    {}
                ).values():
                    groups.update(
                        column.get(
                            "security_groups",
                            {}
                        ).keys()
                    )

    return groups


def _calculate_group_tree_delta(
    root: Dict[str, Any],
    group_name: str,
    action_dependencies: Dict[str, Any],
) -> None:
    root_entry = root.get(
        "security_groups",
        {}
    ).get(
        group_name,
        {}
    )

    root_available = _entry_permissions(
        root_entry
    )

    root_actions = _actions_for_scope(
        root_available,
        action_dependencies,
        allow_child_specific=False,
        unrestricted=root_entry.get("permissions") == ["*"],
    )

    _set_new_allowed_actions(
        root_entry,
        root_actions,
        set(),
    )

    for catalog in root.get(
        "catalogs",
        {}
    ).values():
        catalog_entry = catalog.get(
            "security_groups",
            {}
        ).get(
            group_name,
            {}
        )

        catalog_available = (
            root_available
            | _entry_permissions(catalog_entry)
        )

        catalog_actions = _actions_for_scope(
            catalog_available,
            action_dependencies,
            allow_child_specific=False,
            unrestricted=False,
        )

        _set_new_allowed_actions(
            catalog_entry,
            catalog_actions,
            root_actions,
        )

        for schema in catalog.get(
            "schemas",
            {}
        ).values():
            schema_entry = schema.get(
                "security_groups",
                {}
            ).get(
                group_name,
                {}
            )

            schema_available = (
                catalog_available
                | _entry_permissions(schema_entry)
            )

            schema_actions = _actions_for_scope(
                schema_available,
                action_dependencies,
                allow_child_specific=True,
                unrestricted=False,
            )

            _set_new_allowed_actions(
                schema_entry,
                schema_actions,
                root_actions | catalog_actions,
            )

            for table in schema.get(
                "tables",
                {}
            ).values():
                table_entry = table.get(
                    "security_groups",
                    {}
                ).get(
                    group_name,
                    {}
                )

                table_available = (
                    schema_available
                    | _entry_permissions(table_entry)
                )

                table_actions = _actions_for_scope(
                    table_available,
                    action_dependencies,
                    allow_child_specific=True,
                    unrestricted=False,
                )

                _set_new_allowed_actions(
                    table_entry,
                    table_actions,
                    root_actions
                    | catalog_actions
                    | schema_actions,
                )

                for column in table.get(
                    "columns",
                    {}
                ).values():
                    column_entry = column.get(
                        "security_groups",
                        {}
                    ).get(
                        group_name,
                        {}
                    )

                    column_available = (
                        table_available
                        | _entry_permissions(column_entry)
                    )

                    column_actions = _actions_for_scope(
                        column_available,
                        action_dependencies,
                        allow_child_specific=True,
                        unrestricted=False,
                    )

                    _set_new_allowed_actions(
                        column_entry,
                        column_actions,
                        root_actions
                        | catalog_actions
                        | schema_actions
                        | table_actions,
                    )


def _entry_permissions(
    entry: Dict[str, Any],
) -> set:
    permissions = set(
        entry.get("permissions", [])
    )

    permissions.update(
        _filter_permissions_as_set(
            entry.get("filters")
        )
    )

    return permissions


def _actions_for_scope(
    available: set,
    action_dependencies: Dict[str, Any],
    allow_child_specific: bool,
    unrestricted: bool,
) -> set:
    if unrestricted:
        return {
            name
            for name, requirements in action_dependencies.items()
            if isinstance(requirements, list)
        }

    actions = set()

    for action_name, requirements in action_dependencies.items():
        if not isinstance(requirements, list):
            continue

        if not _requirements_satisfied(
            requirements,
            available,
        ):
            continue

        if (
            not allow_child_specific
            and _has_scope_specific_permission(requirements)
        ):
            continue

        actions.add(action_name)

    return actions


def _set_new_allowed_actions(
    entry: Dict[str, Any],
    current_actions: set,
    inherited_actions: set,
) -> None:
    if not entry:
        return

    new_actions = sorted(
        current_actions - inherited_actions
    )

    if new_actions:
        entry["allowed_actions"] = new_actions


def _requirements_satisfied(
    requirements: List[str],
    available: set,
) -> bool:
    return all(
        requirement in available
        for requirement in requirements
    )


def _filter_permissions_as_set(
    filters: Optional[Dict[str, Any]],
) -> set:
    return set(
        filters.keys()
    ) if filters else set()


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
        set(requirements) & scope_specific
    )


def _prune_empty_tree_nodes(
    node: Dict[str, Any],
) -> None:
    if "security_groups" in node:
        empty_groups = [
            group_name
            for group_name, entry
            in node["security_groups"].items()
            if not entry
        ]

        for group_name in empty_groups:
            del node["security_groups"][group_name]

        if not node["security_groups"]:
            del node["security_groups"]

    for collection_key in (
        "catalogs",
        "schemas",
        "tables",
        "columns",
    ):
        collection = node.get(collection_key)

        if not isinstance(collection, dict):
            continue

        empty_nodes = []

        for name, child in collection.items():
            _prune_empty_tree_nodes(child)

            if not child:
                empty_nodes.append(name)

        for name in empty_nodes:
            del collection[name]

        if not collection:
            del node[collection_key]


def _get_or_create_catalog(
    catalogs: List[Dict[str, Any]],
    catalog_name: str,
) -> Dict[str, Any]:
    for catalog in catalogs:
        if catalog["catalog"] == catalog_name:
            return catalog

    catalog = {
        "catalog": catalog_name,
        "permissions": None,
        "filters": None,
        "schemas": [],
    }

    catalogs.append(catalog)

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
        "permissions": None,
        "filters": None,
        "tables": [],
    }

    schemas.append(schema)

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
        "permissions": None,
        "filters": None,
        "columns": [],
    }

    tables.append(table)

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
        "permissions": None,
        "filters": None,
    }

    columns.append(column)

    return column


def _add_permission(
    node: Dict[str, Any],
    permission: str,
) -> None:
    if node.get("permissions") is None:
        node["permissions"] = []

    _add_unique(
        node["permissions"],
        permission,
    )


def _add_filter(
    node: Dict[str, Any],
    filter_permission: str,
    value: Any,
) -> None:
    if node.get("filters") is None:
        node["filters"] = {}

    if filter_permission not in node["filters"]:
        node["filters"][filter_permission] = []

    existing = node["filters"][filter_permission]

    if not isinstance(existing, list):
        existing = [existing]
        node["filters"][filter_permission] = existing

    if value not in existing:
        existing.append(value)


def _add_unique(
    values: List[str],
    value: str,
) -> None:
    if value not in values:
        values.append(value)


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

        target_group.setdefault(
            "catalogs",
            []
        )

        if source_group.get(
            "global_allow_all",
            False,
        ):
            target_group["global_allow_all"] = True

        _merge_permission_value(
            target_group,
            source_group,
            "permissions",
        )

        _merge_filter_value(
            target_group,
            source_group,
        )

        for source_catalog in source_group.get(
            "catalogs",
            [],
        ):
            target_catalog = _get_or_create_catalog(
                target_group["catalogs"],
                source_catalog["catalog"],
            )

            _merge_permission_value(
                target_catalog,
                source_catalog,
                "permissions",
            )

            _merge_filter_value(
                target_catalog,
                source_catalog,
            )

            for source_schema in source_catalog.get(
                "schemas",
                [],
            ):
                target_schema = _get_or_create_schema(
                    target_catalog["schemas"],
                    source_schema["schema"],
                )

                _merge_permission_value(
                    target_schema,
                    source_schema,
                    "permissions",
                )

                _merge_filter_value(
                    target_schema,
                    source_schema,
                )

                for source_table in source_schema.get(
                    "tables",
                    [],
                ):
                    target_table = _get_or_create_table(
                        target_schema["tables"],
                        source_table["table"],
                    )

                    _merge_permission_value(
                        target_table,
                        source_table,
                        "permissions",
                    )

                    _merge_filter_value(
                        target_table,
                        source_table,
                    )

                    for source_column in source_table.get(
                        "columns",
                        [],
                    ):
                        target_column = _get_or_create_column(
                            target_table["columns"],
                            source_column["column"],
                        )

                        _merge_permission_value(
                            target_column,
                            source_column,
                            "permissions",
                        )

                        _merge_filter_value(
                            target_column,
                            source_column,
                        )


def _merge_permission_value(
    target: Dict[str, Any],
    source: Dict[str, Any],
    key: str,
) -> None:
    source_value = source.get(key)
    target_value = target.get(key)

    if source_value is None:
        return

    if target_value is None:
        target[key] = list(source_value)
        return

    for permission in source_value:
        _add_unique(
            target_value,
            permission,
        )


def _merge_filter_value(
    target: Dict[str, Any],
    source: Dict[str, Any],
) -> None:
    source_filters = source.get("filters")

    if source_filters is None:
        return

    target_filters = target.get("filters")

    if target_filters is None:
        target["filters"] = _deep_copy_json(
            source_filters
        )
        return

    for filter_name, source_values in source_filters.items():
        if filter_name not in target_filters:
            target_filters[filter_name] = _deep_copy_json(
                source_values
            )
            continue

        target_values = target_filters[filter_name]

        if not isinstance(target_values, list):
            target_values = [target_values]
            target_filters[filter_name] = target_values

        if isinstance(source_values, list):
            for value in source_values:
                if value not in target_values:
                    target_values.append(
                        _deep_copy_json(value)
                    )


def _deep_copy_json(value: Any) -> Any:
    return json.loads(
        json.dumps(value)
    )


def _combine_rego_files(
    opa_directory: str,
) -> Path:
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
                "\n\n# ============================================================\n"
            )

            temporary_file.write(
                f"# FILE: {opa_file.name}\n"
            )

            temporary_file.write(
                "# ============================================================\n\n"
            )

            temporary_file.write(content)
            temporary_file.write("\n\n")

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


def build_permission_tree_from_directory(
    opa_directory: str,
    action_permissions_file: str,
    security_groups_file: str,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
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
            opa_file=str(temporary_rego),
            action_permissions_file=action_permissions_file,
            security_groups_file=security_groups_file,
        )

        if output_file is not None:
            _write_permission_tree(
                actual_tree,
                output_file,
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
        opa_directory=str(OPA_DIRECTORY),
        action_permissions_file=str(ACTION_PERMISSIONS_FILE),
        security_groups_file=str(SECURITY_GROUPS_FILE),
        output_file=str(OUTPUT_FILE),
    )

    print("\nPermission tree:")
    print(
        json.dumps(
            tree,
            indent=2,
            ensure_ascii=False,
        )
    )