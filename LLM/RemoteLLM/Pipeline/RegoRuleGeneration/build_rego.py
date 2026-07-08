import json
import os

# resource "type" -> the fields Trino puts under input.action.resource.<type>
RESOURCE_FIELD_MAP = {
    "catalog": ["catalogName"],
    "schema": ["catalogName", "schemaName"],
    "table": ["catalogName", "schemaName", "tableName"],
    "column": ["catalogName", "schemaName", "tableName", "columnName"],
}

def build_rego(entities, check_for_action, valid_actions):
    subject_attr = entities["subject_attribute"]
    subject_val = entities["subject_value"]
    trino_action = entities["trino_action"]
    resource_type = entities["resource_type"]
    resource_values = entities.get("resource_values", {})

    if trino_action != "*" and trino_action not in check_for_action:
        raise ValueError(
            f"'{trino_action}' is not a known Trino action. "
            f"Valid actions: {valid_actions}"
        )

    checks = check_for_action.get(trino_action, [])

    if trino_action == "*":
        operation_check = ""
    else:
        checks_set = ", ".join(f'"{c}"' for c in checks)
        operation_check = f"input.action.operation in {{{checks_set}}}"

    if trino_action != "*" and not checks:
        raise ValueError(f"'{trino_action}' has no associated OPA checks defined.")

    # --- identity match -----------------------------------------------
    if subject_attr == "groups":
        identity_check = f'input.context.identity.groups[_] == "{subject_val}"'
    else:
        identity_check = f'input.context.identity.user == "{subject_val}"'

    # --- resource match, following input.json's real shape -------------
    resource_lines = []
    fields = RESOURCE_FIELD_MAP.get(resource_type, [])
    for field in fields:
        val = resource_values.get(field)
        if val:
            resource_lines.append(
                f'    input.action.resource.{resource_type}.{field} == "{val}"'
            )

    body_lines = [identity_check]
    if operation_check:
        body_lines.append(operation_check)
    body_lines.extend(resource_lines)

    body = "\n".join(f"    {line}" for line in body_lines)

    return f"""package authz

import future.keywords.if
import future.keywords.in

default allow := false

# Trino action "{trino_action}" triggers these OPA checks: {checks}
allow if {{
{body}
}}
"""
