import json
import numpy as np

from LLM.Interface.embedding_call import embedding_call
from LLM.Interface.llm_call import llm_call


# ============================================================================
# Similarity
# ============================================================================

def cosine_similarity(a, b):
    denominator = np.linalg.norm(a) * np.linalg.norm(b)

    if denominator == 0:
        return 0.0

    return float(np.dot(a, b) / denominator)


# ============================================================================
# Retrieve examples
# ============================================================================

def find_best_examples(
    rule,
    index,
    is_local,
    n=3,
    embedding_url=None,
    client=None,
    embedding_model=None,
):
    query_embedding = embedding_call(
        text=rule,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model,
    )

    ranked = sorted(
        index,
        key=lambda example: cosine_similarity(
            query_embedding,
            example["embedding"],
        ),
        reverse=True,
    )

    return ranked[:n]


# ============================================================================
# Generic JSON LLM call
# ============================================================================

def _llm_json(
    system_prompt,
    user_prompt,
    is_local,
    chat_url=None,
    client=None,
    model=None,
):
    messages = [
        {
            "role": "system",
            "content": system_prompt,
        },
        {
            "role": "user",
            "content": user_prompt,
        },
    ]

    response = llm_call(
        json.dumps(messages, indent=2),
        temperature=0.0,
        response_format={
            "type": "json_object"
        },
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    response = response.strip()

    try:
        return json.loads(response)

    except json.JSONDecodeError as e:
        raise ValueError(
            f"LLM returned invalid JSON:\n{response}"
        ) from e


# ============================================================================
# Security group extraction
# ============================================================================

def _extract_security_group(
    rule,
    security_groups,
    is_local,
    chat_url=None,
    client=None,
    model=None,
):
    system_prompt = """
You extract the security group from a natural language access rule.

You MUST NOT validate the group against any external knowledge.

Return ONLY JSON:

{
  "security_group": null
}

If a security group or role is explicitly mentioned, return its exact
meaning as a string.

Do not invent a group.

If no group can be identified, return null.
"""

    result = _llm_json(
        system_prompt,
        (
            "Available security groups are:\n"
            f"{json.dumps(security_groups, indent=2)}\n\n"
            "Rule:\n"
            f"{rule}"
        ),
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    group = result.get("security_group")

    if not group:
        return {
            "security_group": None,
            "existSecureGroup": False,
            "feedback": (
                "No security group could be identified in the request."
            ),
        }

    # Deterministic validation.
    if group in security_groups:
        return {
            "security_group": group,
            "existSecureGroup": True,
            "feedback": "",
        }

    return {
        "security_group": group,
        "existSecureGroup": False,
        "feedback": (
            f"The security group '{group}' does not exist. "
            f"Available security groups are: "
            f"{', '.join(repr(x) for x in security_groups)}."
        ),
    }


# ============================================================================
# Resource extraction
# ============================================================================

def _extract_resource(
    rule,
    data_mesh_structure,
    is_local,
    chat_url=None,
    client=None,
    model=None,
):
    system_prompt = """
You extract the requested data resource from a natural language rule.

The resource may contain:

- catalog
- schema
- table
- column

Return ONLY JSON with exactly this structure:

{
  "catalog": null,
  "schema": null,
  "table": null,
  "column": null
}

Rules:

1. Extract only resources explicitly present or clearly implied by the rule.
2. Do not invent names.
3. Do not validate whether the resource exists.
4. Do not replace an invalid name with a valid one.
5. Preserve the user's requested resource exactly.
6. A schema-only request may have catalog and schema but no table.
7. A table request should normally contain catalog, schema and table.
8. A column request should contain catalog, schema, table and column.

Return null for values that are not present.
"""

    result = _llm_json(
        system_prompt,
        (
            "Data Mesh Structure:\n"
            f"{json.dumps(data_mesh_structure, indent=2)}\n\n"
            "Rule:\n"
            f"{rule}"
        ),
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    return {
        "catalog": result.get("catalog"),
        "schema": result.get("schema"),
        "table": result.get("table"),
        "column": result.get("column"),
    }


# ============================================================================
# Data Mesh traversal
# ============================================================================

def _find_catalog(data_mesh_structure, catalog_name):
    """
    Expected structure:

    {
        "catalogs": [
            {
                "name": "iceberg",
                "schemas": [...]
            }
        ]
    }
    """

    if not isinstance(data_mesh_structure, dict):
        return None

    catalogs = data_mesh_structure.get("catalogs", [])

    if not isinstance(catalogs, list):
        return None

    for catalog in catalogs:
        if not isinstance(catalog, dict):
            continue

        if catalog.get("name") == catalog_name:
            return catalog

    return None


def _find_schema(catalog, schema_name):
    if not isinstance(catalog, dict):
        return None

    schemas = catalog.get("schemas", [])

    if not isinstance(schemas, list):
        return None

    for schema in schemas:
        if not isinstance(schema, dict):
            continue

        if schema.get("name") == schema_name:
            return schema

    return None


def _find_table(schema, table_name):
    if not isinstance(schema, dict):
        return None

    tables = schema.get("tables", [])

    if not isinstance(tables, list):
        return None

    for table in tables:
        if not isinstance(table, dict):
            continue

        if table.get("name") == table_name:
            return table

    return None


def _validate_resource_path(
    resource,
    data_mesh_structure,
):
    catalog_name = resource.get("catalog")
    schema_name = resource.get("schema")
    table_name = resource.get("table")
    column_name = resource.get("column")

    # ------------------------------------------------------------
    # No resource at all
    # ------------------------------------------------------------

    if not any(
        [
            catalog_name,
            schema_name,
            table_name,
            column_name,
        ]
    ):
        return {
            "valid": True,
            "feedback": "",
        }

    # ------------------------------------------------------------
    # Catalog
    # ------------------------------------------------------------

    if catalog_name:
        catalog = _find_catalog(
            data_mesh_structure,
            catalog_name,
        )

        if catalog is None:
            catalogs = data_mesh_structure.get(
                "catalogs",
                [],
            )

            available = [
                c.get("name")
                for c in catalogs
                if isinstance(c, dict)
                and c.get("name")
            ]

            return {
                "valid": False,
                "feedback": (
                    f"The catalog '{catalog_name}' does not exist. "
                    f"Available catalogs are: "
                    f"{', '.join(repr(x) for x in available)}."
                ),
            }

    else:
        return {
            "valid": False,
            "feedback": (
                "The request contains a resource but no catalog "
                "could be identified."
            ),
        }

    # ------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------

    if schema_name:
        schema = _find_schema(
            catalog,
            schema_name,
        )

        if schema is None:
            available = [
                s.get("name")
                for s in catalog.get("schemas", [])
                if isinstance(s, dict)
                and s.get("name")
            ]

            return {
                "valid": False,
                "feedback": (
                    f"The schema '{schema_name}' does not exist "
                    f"in catalog '{catalog_name}'. "
                    f"Available schemas are: "
                    f"{', '.join(repr(x) for x in available)}."
                ),
            }

    else:
        # Catalog-only request is valid.
        return {
            "valid": True,
            "feedback": "",
        }

    # ------------------------------------------------------------
    # Table
    # ------------------------------------------------------------

    if table_name:
        table = _find_table(
            schema,
            table_name,
        )

        if table is None:
            available = [
                t.get("name")
                for t in schema.get("tables", [])
                if isinstance(t, dict)
                and t.get("name")
            ]

            return {
                "valid": False,
                "feedback": (
                    f"The table '{table_name}' does not exist "
                    f"in catalog '{catalog_name}', "
                    f"schema '{schema_name}'. "
                    f"Available tables are: "
                    f"{', '.join(repr(x) for x in available)}."
                ),
            }

    else:
        # Schema-only request is valid.
        return {
            "valid": True,
            "feedback": "",
        }

    # ------------------------------------------------------------
    # Column
    # ------------------------------------------------------------

    if column_name:
        columns = table.get(
            "columns",
            [],
        )

        column_names = []

        for column in columns:
            if isinstance(column, dict):
                name = column.get("name")
                if name:
                    column_names.append(name)

            elif isinstance(column, str):
                column_names.append(column)

        if column_name not in column_names:
            return {
                "valid": False,
                "feedback": (
                    f"The column '{column_name}' does not exist "
                    f"in catalog '{catalog_name}', "
                    f"schema '{schema_name}', "
                    f"table '{table_name}'. "
                    f"Available columns are: "
                    f"{', '.join(repr(x) for x in column_names)}."
                ),
            }

    return {
        "valid": True,
        "feedback": "",
    }


# ============================================================================
# Action extraction
# ============================================================================

def _extract_actions(
    rule,
    available_actions,
    is_local,
    chat_url=None,
    client=None,
    model=None,
):
    system_prompt = """
You identify the intended operation(s) in a natural language data access
request.

Available actions are supplied by the caller.

IMPORTANT:

- Do not invent actions.
- Do not assume any action not present in Available Actions.
- Do not treat Available Actions as a permission mapping.
- First understand what the user wants.
- Then map that intent to the closest action(s) from the supplied list.
- If no supplied action represents the intent, return null for that intent.
- A request may contain multiple operations.
- "access", "read", "consult", "use", "look at" are generic language.
  Do not invent an action merely because those words appear.

Return ONLY JSON:

{
  "requested_actions": [
    {
      "intent": "<natural language operation>",
      "action": null
    }
  ]
}

The action value MUST either:
- be one of the supplied Available Actions
- or be null if no supplied action represents the intent.
"""

    result = _llm_json(
        system_prompt,
        (
            "Available Actions:\n"
            f"{json.dumps(available_actions, indent=2)}\n\n"
            "Rule:\n"
            f"{rule}"
        ),
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    requested_actions = result.get(
        "requested_actions",
        [],
    )

    if not isinstance(requested_actions, list):
        requested_actions = []

    return requested_actions


# ============================================================================
# Validate actions
# ============================================================================

def _validate_actions(
    requested_actions,
    available_actions,
):
    if not requested_actions:
        return {
            "valid": False,
            "feedback": (
                "No actionable operation could be identified "
                "from the request."
            ),
        }

    invalid = []
    valid = []

    for item in requested_actions:
        if not isinstance(item, dict):
            continue

        intent = item.get(
            "intent",
            "",
        )

        action = item.get(
            "action"
        )

        if action is None:
            invalid.append(
                {
                    "intent": intent,
                    "action": None,
                }
            )

        elif action not in available_actions:
            invalid.append(
                {
                    "intent": intent,
                    "action": action,
                }
            )

        else:
            valid.append(action)

    if invalid:
        messages = []

        for item in invalid:
            if item["action"] is None:
                messages.append(
                    f"The requested operation '{item['intent']}' "
                    f"could not be mapped to any available action."
                )
            else:
                messages.append(
                    f"The inferred action '{item['action']}' is not "
                    f"in the available actions."
                )

        messages.append(
            "Available actions are: "
            + ", ".join(available_actions)
        )

        return {
            "valid": False,
            "feedback": " ".join(messages),
        }

    return {
        "valid": True,
        "feedback": "",
    }


# ============================================================================
# Final explanation
# ============================================================================

def _generate_final_explanation(
    rule,
    security_group_result,
    resource,
    action_result,
    path_result,
    is_local,
    chat_url=None,
    client=None,
    model=None,
):
    system_prompt = """
You produce the final explanation for a validated Trino access request.

Return ONLY JSON:

{
  "text": "",
  "llm_feedback": ""
}

Rules:

1. Describe the ORIGINAL request.
2. Never silently correct the original request.
3. If everything is valid, llm_feedback must be "".
4. If something is invalid, explain all invalid parts.
5. Use the extracted security group, resource and actions.
6. Do not invent any information.
7. Keep the explanation concise.
"""

    context = {
        "rule": rule,
        "security_group": security_group_result,
        "resource": resource,
        "actions": action_result,
        "path_validation": path_result,
    }

    result = _llm_json(
        system_prompt,
        json.dumps(
            context,
            indent=2,
        ),
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    return {
        "text": result.get(
            "text",
            rule,
        ),
        "llm_feedback": result.get(
            "llm_feedback",
            "",
        ),
    }


# ============================================================================
# Main function
# ============================================================================

def llm_explain(
    rule,
    example_index,
    data_mesh_structure,
    security_groups,
    available_actions,
    is_local,
    n=3,
    chat_url=None,
    embedding_url=None,
    client=None,
    model=None,
    embedding_model=None,
):
    # ------------------------------------------------------------------------
    # Retrieve examples.
    #
    # Examples are used ONLY as semantic/contextual references.
    # They are NEVER authoritative.
    # ------------------------------------------------------------------------

    examples = []

    if example_index:
        examples = find_best_examples(
            rule,
            example_index,
            is_local,
            n=n,
            embedding_url=embedding_url,
            client=client,
            embedding_model=embedding_model,
        )

    # ------------------------------------------------------------------------
    # 1. Security group
    # ------------------------------------------------------------------------

    security_group_result = _extract_security_group(
        rule=rule,
        security_groups=security_groups,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    # ------------------------------------------------------------------------
    # 2. Resource
    # ------------------------------------------------------------------------

    resource = _extract_resource(
        rule=rule,
        data_mesh_structure=data_mesh_structure,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    # ------------------------------------------------------------------------
    # 3. Deterministic Data Mesh validation
    #
    # IMPORTANT:
    # The LLM extracts the path.
    # Python validates the path.
    # ------------------------------------------------------------------------

    path_result = _validate_resource_path(
        resource,
        data_mesh_structure,
    )

    # ------------------------------------------------------------------------
    # 4. Action interpretation
    # ------------------------------------------------------------------------

    requested_actions = _extract_actions(
        rule=rule,
        available_actions=available_actions,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    # ------------------------------------------------------------------------
    # 5. Deterministic action validation
    # ------------------------------------------------------------------------

    action_result = _validate_actions(
        requested_actions,
        available_actions,
    )

    # ------------------------------------------------------------------------
    # 6. Final explanation
    # ------------------------------------------------------------------------

    final = _generate_final_explanation(
        rule=rule,
        security_group_result=security_group_result,
        resource=resource,
        action_result=action_result,
        path_result=path_result,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    # ------------------------------------------------------------------------
    # 7. Combine feedback
    # ------------------------------------------------------------------------

    feedback = []

    if security_group_result["feedback"]:
        feedback.append(
            security_group_result["feedback"]
        )

    if path_result["feedback"]:
        feedback.append(
            path_result["feedback"]
        )

    if action_result["feedback"]:
        feedback.append(
            action_result["feedback"]
        )

    # Final LLM feedback is useful only if there are no deterministic
    # validation errors.
    if final["llm_feedback"]:
        feedback.append(
            final["llm_feedback"]
        )

    # ------------------------------------------------------------------------
    # 8. Final result
    # ------------------------------------------------------------------------

    return {
        "text": final["text"],
        "existSecureGroup": security_group_result[
            "existSecureGroup"
        ],
        "pathExistOnDataMeshStructure": path_result[
            "valid"
        ],
        "actionExist": action_result[
            "valid"
        ],
        "llm_feedback": " ".join(feedback),
    }