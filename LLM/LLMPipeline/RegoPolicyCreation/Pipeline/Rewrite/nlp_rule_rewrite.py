import json
import numpy as np

from LLM.Interface.embedding_call import embedding_call
from LLM.Interface.llm_call import llm_call


# ============================================================================
# Constants
# ============================================================================

RESOURCE_FIELDS = {
    "catalog",
    "schema",
    "table",
    "column",
}

AVAILABLE_ACTION_FIELDS = {
    "intent",
    "action",
}


# ============================================================================
# Data Mesh traversal
# ============================================================================

def _get_catalogs(data_mesh_structure):
    """
    Return the authoritative list of catalogs.

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
        return []

    catalogs = data_mesh_structure.get("catalogs", [])

    if not isinstance(catalogs, list):
        return []

    return catalogs


def _find_catalog(data_mesh_structure, catalog_name):
    """Find a catalog by exact name."""

    if not catalog_name:
        return None

    for catalog in _get_catalogs(data_mesh_structure):

        if not isinstance(catalog, dict):
            continue

        if catalog.get("name") == catalog_name:
            return catalog

    return None


def _find_schema(catalog, schema_name):
    """Find a schema inside a catalog by exact name."""

    if not isinstance(catalog, dict):
        return None

    if not schema_name:
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
    """Find a table inside a schema by exact name."""

    if not isinstance(schema, dict):
        return None

    if not table_name:
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


def _get_columns(table):
    """
    Return normalized column names.

    Supports:

        "columns": [
            "employee_id",
            "salary"
        ]

    and:

        "columns": [
            {
                "name": "employee_id",
                "type": "varchar"
            }
        ]
    """

    if not isinstance(table, dict):
        return []

    columns = table.get("columns", [])

    if not isinstance(columns, list):
        return []

    result = []

    for column in columns:

        if isinstance(column, str):

            if column:
                result.append(column)

        elif isinstance(column, dict):

            name = column.get("name")

            if isinstance(name, str) and name:
                result.append(name)

    return result


def _get_schema_names(catalog):
    """Return all schema names from a catalog."""

    if not isinstance(catalog, dict):
        return []

    schemas = catalog.get("schemas", [])

    if not isinstance(schemas, list):
        return []

    result = []

    for schema in schemas:

        if not isinstance(schema, dict):
            continue

        name = schema.get("name")

        if isinstance(name, str) and name:
            result.append(name)

    return result


def _get_table_names(schema):
    """Return all table names from a schema."""

    if not isinstance(schema, dict):
        return []

    tables = schema.get("tables", [])

    if not isinstance(tables, list):
        return []

    result = []

    for table in tables:

        if not isinstance(table, dict):
            continue

        name = table.get("name")

        if isinstance(name, str) and name:
            result.append(name)

    return result


def _get_column_names(table):
    """Alias kept for readability."""

    return _get_columns(table)


# ============================================================================
# Catalog inference
# ============================================================================

def _infer_unique_catalog(
    data_mesh_structure,
    schema_name,
):
    """
    Infer a catalog only when exactly one catalog contains
    the requested schema.

    Example:

        schema = finance

    If only iceberg.finance exists:

        catalog = iceberg

    If finance exists in multiple catalogs:

        catalog remains unknown.
    """

    if not schema_name:
        return None

    matches = []

    for catalog in _get_catalogs(data_mesh_structure):

        if not isinstance(catalog, dict):
            continue

        schema = _find_schema(
            catalog,
            schema_name,
        )

        if schema is not None:

            catalog_name = catalog.get("name")

            if catalog_name:
                matches.append(catalog_name)

    if len(matches) == 1:
        return matches[0]

    return None


# ============================================================================
# Resource validation
# ============================================================================

def _validate_resource_path(
    resource,
    data_mesh_structure,
):
    """
    Deterministically validate:

        catalog
            -> schema
                -> table
                    -> column

    against the authoritative Data Mesh Structure.

    The LLM does not determine whether a resource exists.

    No resource is replaced with another resource.
    No wildcard is generated.
    """

    if not isinstance(resource, dict):
        return {
            "valid": False,
            "feedback": "The extracted resource is not a valid object.",
        }

    catalog_name = resource.get("catalog")
    schema_name = resource.get("schema")
    table_name = resource.get("table")
    column_name = resource.get("column")

    # ------------------------------------------------------------------------
    # Normalize empty strings to None
    # ------------------------------------------------------------------------

    for field in RESOURCE_FIELDS:

        value = resource.get(field)

        if isinstance(value, str):
            value = value.strip()

            if value == "":
                value = None

            resource[field] = value

    catalog_name = resource.get("catalog")
    schema_name = resource.get("schema")
    table_name = resource.get("table")
    column_name = resource.get("column")

    # ------------------------------------------------------------------------
    # No resource specified
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # Validate hierarchy syntax
    #
    # A table requires a schema.
    # A column requires a table.
    # ------------------------------------------------------------------------

    if column_name and not table_name:

        return {
            "valid": False,
            "feedback": (
                f"The column '{column_name}' was specified without "
                "a table."
            ),
        }

    if table_name and not schema_name:

        return {
            "valid": False,
            "feedback": (
                f"The table '{table_name}' was specified without "
                "a schema."
            ),
        }

    # ------------------------------------------------------------------------
    # Infer catalog only from an unambiguous schema
    # ------------------------------------------------------------------------

    if catalog_name is None and schema_name:

        inferred_catalog = _infer_unique_catalog(
            data_mesh_structure,
            schema_name,
        )

        if inferred_catalog:

            resource["catalog"] = inferred_catalog
            catalog_name = inferred_catalog

        else:

            catalogs = _get_catalogs(
                data_mesh_structure
            )

            matching_catalogs = []

            for catalog in catalogs:

                if not isinstance(catalog, dict):
                    continue

                if _find_schema(
                    catalog,
                    schema_name,
                ) is not None:

                    name = catalog.get("name")

                    if name:
                        matching_catalogs.append(name)

            if len(matching_catalogs) > 1:

                return {
                    "valid": False,
                    "feedback": (
                        f"The schema '{schema_name}' exists in multiple "
                        "catalogs: "
                        + ", ".join(
                            repr(x)
                            for x in matching_catalogs
                        )
                        + ". A catalog must be specified."
                    ),
                }

            return {
                "valid": False,
                "feedback": (
                    f"The schema '{schema_name}' could not be resolved "
                    "to a unique catalog."
                ),
            }

    # ------------------------------------------------------------------------
    # Resource exists but catalog is still unknown
    # ------------------------------------------------------------------------

    if not catalog_name:

        return {
            "valid": False,
            "feedback": (
                "The request contains a resource but no catalog "
                "could be identified."
            ),
        }

    # ------------------------------------------------------------------------
    # Catalog
    # ------------------------------------------------------------------------

    catalog = _find_catalog(
        data_mesh_structure,
        catalog_name,
    )

    if catalog is None:

        available = []

        for item in _get_catalogs(
            data_mesh_structure
        ):

            if not isinstance(item, dict):
                continue

            name = item.get("name")

            if name:
                available.append(name)

        return {
            "valid": False,
            "feedback": (
                f"The catalog '{catalog_name}' does not exist. "
                "Available catalogs are: "
                + (
                    ", ".join(
                        repr(x)
                        for x in available
                    )
                    if available
                    else "none"
                )
                + "."
            ),
        }

    # ------------------------------------------------------------------------
    # Catalog-only request
    # ------------------------------------------------------------------------

    if not schema_name:

        return {
            "valid": True,
            "feedback": "",
        }

    # ------------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------------

    schema = _find_schema(
        catalog,
        schema_name,
    )

    if schema is None:

        available = _get_schema_names(
            catalog
        )

        return {
            "valid": False,
            "feedback": (
                f"The schema '{schema_name}' does not exist "
                f"in catalog '{catalog_name}'. "
                "Available schemas are: "
                + (
                    ", ".join(
                        repr(x)
                        for x in available
                    )
                    if available
                    else "none"
                )
                + "."
            ),
        }

    # ------------------------------------------------------------------------
    # Schema-only request
    # ------------------------------------------------------------------------

    if not table_name:

        return {
            "valid": True,
            "feedback": "",
        }

    # ------------------------------------------------------------------------
    # Table
    # ------------------------------------------------------------------------

    table = _find_table(
        schema,
        table_name,
    )

    if table is None:

        available = _get_table_names(
            schema
        )

        return {
            "valid": False,
            "feedback": (
                f"The table '{table_name}' does not exist "
                f"in catalog '{catalog_name}', "
                f"schema '{schema_name}'. "
                "Available tables are: "
                + (
                    ", ".join(
                        repr(x)
                        for x in available
                    )
                    if available
                    else "none"
                )
                + "."
            ),
        }

    # ------------------------------------------------------------------------
    # Table-only request
    # ------------------------------------------------------------------------

    if not column_name:

        return {
            "valid": True,
            "feedback": "",
        }

    # ------------------------------------------------------------------------
    # Column
    # ------------------------------------------------------------------------

    column_names = _get_column_names(
        table
    )

    if column_name not in column_names:

        return {
            "valid": False,
            "feedback": (
                f"The column '{column_name}' does not exist "
                f"in catalog '{catalog_name}', "
                f"schema '{schema_name}', "
                f"table '{table_name}'. "
                "Available columns are: "
                + (
                    ", ".join(
                        repr(x)
                        for x in column_names
                    )
                    if column_names
                    else "none"
                )
                + "."
            ),
        }

    return {
        "valid": True,
        "feedback": "",
    }


# ============================================================================
# Resource expansion
# ============================================================================

def _make_expanded_resource(
    catalog_name,
    schema_name,
    table_name,
    column_name="",
):
    """
    Create the canonical expanded resource representation.

    IMPORTANT:

    Empty columnName means the table itself.

    It never means "*".
    """

    return {
        "catalogName": catalog_name,
        "schemaName": schema_name,
        "tableName": table_name,
        "columnName": column_name,
    }


def _expand_table(
    catalog_name,
    schema_name,
    table,
):
    """
    Expand one table.

    A table is represented once with an empty columnName.

    We intentionally do NOT expand a table into all its columns.

    This is important because:

        table-level request != column-level request
    """

    if not isinstance(table, dict):
        return []

    table_name = table.get("name")

    if not table_name:
        return []

    return [
        _make_expanded_resource(
            catalog_name=catalog_name,
            schema_name=schema_name,
            table_name=table_name,
            column_name="",
        )
    ]


def _expand_schema(
    catalog_name,
    schema_name,
    schema,
):
    """
    Expand a schema into all existing tables.

    No wildcard is generated.
    """

    if not isinstance(schema, dict):
        return []

    result = []

    tables = schema.get("tables", [])

    if not isinstance(tables, list):
        return result

    for table in tables:

        result.extend(
            _expand_table(
                catalog_name,
                schema_name,
                table,
            )
        )

    return result


def _expand_catalog(
    catalog_name,
    catalog,
):
    """
    Expand a catalog into all existing schemas and tables.

    No wildcard is generated.
    """

    if not isinstance(catalog, dict):
        return []

    result = []

    schemas = catalog.get("schemas", [])

    if not isinstance(schemas, list):
        return result

    for schema in schemas:

        if not isinstance(schema, dict):
            continue

        schema_name = schema.get("name")

        if not schema_name:
            continue

        result.extend(
            _expand_schema(
                catalog_name,
                schema_name,
                schema,
            )
        )

    return result


def _expand_resource(
    resource,
    data_mesh_structure,
):
    """
    Deterministically expand an already validated resource.

    Rules:

        catalog
            -> every existing table

        catalog + schema
            -> every existing table in schema

        catalog + schema + table
            -> exactly that table

        catalog + schema + table + column
            -> exactly that column

    IMPORTANT:

    There is NEVER a "*" value.
    """

    if not isinstance(resource, dict):
        return []

    catalog_name = resource.get("catalog")
    schema_name = resource.get("schema")
    table_name = resource.get("table")
    column_name = resource.get("column")

    if not catalog_name:
        return []

    catalog = _find_catalog(
        data_mesh_structure,
        catalog_name,
    )

    if catalog is None:
        return []

    # ------------------------------------------------------------------------
    # Catalog
    # ------------------------------------------------------------------------

    if not schema_name:

        return _expand_catalog(
            catalog_name,
            catalog,
        )

    # ------------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------------

    schema = _find_schema(
        catalog,
        schema_name,
    )

    if schema is None:
        return []

    if not table_name:

        return _expand_schema(
            catalog_name,
            schema_name,
            schema,
        )

    # ------------------------------------------------------------------------
    # Table
    # ------------------------------------------------------------------------

    table = _find_table(
        schema,
        table_name,
    )

    if table is None:
        return []

    # ------------------------------------------------------------------------
    # Table-only
    # ------------------------------------------------------------------------

    if not column_name:

        return [
            _make_expanded_resource(
                catalog_name=catalog_name,
                schema_name=schema_name,
                table_name=table_name,
                column_name="",
            )
        ]

    # ------------------------------------------------------------------------
    # Column
    # ------------------------------------------------------------------------

    columns = _get_column_names(
        table
    )

    if column_name not in columns:
        return []

    return [
        _make_expanded_resource(
            catalog_name=catalog_name,
            schema_name=schema_name,
            table_name=table_name,
            column_name=column_name,
        )
    ]


# ============================================================================
# Similarity
# ============================================================================

def cosine_similarity(a, b):
    denominator = (
        np.linalg.norm(a)
        *
        np.linalg.norm(b)
    )

    if denominator == 0:
        return 0.0

    return float(
        np.dot(a, b)
        /
        denominator
    )


# ============================================================================
# Retrieve semantic examples
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
    if not index:
        return []

    query_embedding = embedding_call(
        text=rule,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model,
    )

    ranked = []

    for example in index:

        if not isinstance(example, dict):
            continue

        embedding = example.get("embedding")

        if embedding is None:
            continue

        ranked.append(
            (
                cosine_similarity(
                    query_embedding,
                    embedding,
                ),
                example,
            )
        )

    ranked.sort(
        key=lambda item: item[0],
        reverse=True,
    )

    return [
        example
        for _, example in ranked[:n]
    ]


# ============================================================================
# Action helpers
# ============================================================================

def _normalize_available_actions(
    available_actions,
):
    """
    Normalize the authoritative available action list.
    """

    if not isinstance(
        available_actions,
        list,
    ):
        return []

    result = []

    for action in available_actions:

        if isinstance(action, str):

            action = action.strip()

            if action and action not in result:
                result.append(action)

    return result


def _build_action_existence(
    requested_actions,
    available_actions,
):
    """
    Build deterministic action existence information.
    """

    available = set(
        available_actions
    )

    result = []

    for item in requested_actions:

        if not isinstance(item, dict):
            continue

        action_name = item.get(
            "action"
        )

        if action_name is None:
            result.append(
                {
                    "action": None,
                    "exists": False,
                }
            )
            continue

        result.append(
            {
                "action": action_name,
                "exists": action_name in available,
            }
        )

    return result


def _validate_actions(
    requested_actions,
    available_actions,
):
    """
    Deterministically validate actions.

    The LLM may propose an action, but Python decides
    whether it is actually available.
    """

    if not isinstance(
        requested_actions,
        list,
    ) or not requested_actions:

        return {
            "valid": False,
            "feedback": (
                "No actionable operation could be identified "
                "from the request."
            ),
        }

    available = set(
        available_actions
    )

    invalid = []
    valid = []

    for item in requested_actions:

        if not isinstance(item, dict):

            invalid.append(
                {
                    "intent": "",
                    "action": None,
                }
            )

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

            continue

        if action not in available:

            invalid.append(
                {
                    "intent": intent,
                    "action": action,
                }
            )

            continue

        valid.append(
            action
        )

    if invalid:

        messages = []

        for item in invalid:

            if item["action"] is None:

                messages.append(
                    f"The requested operation "
                    f"'{item['intent']}' could not be mapped "
                    "to any available action."
                )

            else:

                messages.append(
                    f"The inferred action "
                    f"'{item['action']}' is not in the "
                    "available actions."
                )

        messages.append(
            "Available actions are: "
            + (
                ", ".join(
                    available_actions
                )
                if available_actions
                else "none"
            )
            + "."
        )

        return {
            "valid": False,
            "feedback": " ".join(messages),
        }

    if not valid:

        return {
            "valid": False,
            "feedback": (
                "No valid Trino actions were identified."
            ),
        }

    return {
        "valid": True,
        "feedback": "",
    }


# ============================================================================
# JSON helpers
# ============================================================================

def _clean_json_response(response):
    """
    Clean common formatting errors produced by local LLMs.

    Accepts:

        {"key": "value"}

    and:

        ```json
        {"key": "value"}
        ```

    and responses containing explanatory text before/after
    the JSON object.
    """

    if response is None:
        raise ValueError(
            "LLM returned no response."
        )

    response = str(response).strip()

    if not response:
        raise ValueError(
            "LLM returned an empty response."
        )

    # ------------------------------------------------------------------
    # Remove markdown code fences
    # ------------------------------------------------------------------

    if response.startswith("```"):

        lines = response.splitlines()

        cleaned_lines = []

        for line in lines:

            stripped = line.strip()

            if stripped.startswith("```"):
                continue

            cleaned_lines.append(
                line
            )

        response = "\n".join(
            cleaned_lines
        ).strip()

    # ------------------------------------------------------------------
    # Locate the first JSON object.
    # ------------------------------------------------------------------

    start = response.find("{")

    if start < 0:
        raise ValueError(
            "LLM response does not contain a JSON object:\n"
            + response
        )

    # ------------------------------------------------------------------
    # Locate the matching final closing brace.
    #
    # rfind is sufficient here because the expected response is
    # a single JSON object.
    # ------------------------------------------------------------------

    end = response.rfind("}")

    if end < start:
        raise ValueError(
            "LLM response contains an incomplete JSON object:\n"
            + response
        )

    response = response[
        start:end + 1
    ].strip()

    return response



def _llm_json(
    system_prompt,
    user_prompt,
    is_local,
    chat_url=None,
    client=None,
    model=None,
):
    """
    Execute an LLM request and require a JSON object.

    The OpenAI-compatible JSON response format requires the word
    "json" to appear somewhere in the messages when using:

        response_format={"type": "json_object"}

    Therefore this function explicitly injects a JSON instruction
    into the system message instead of relying on every individual
    extraction prompt to contain it.
    """

    # ------------------------------------------------------------------
    # IMPORTANT:
    #
    # Some OpenAI-compatible servers validate that the literal word
    # "json" appears in the messages when response_format=json_object
    # is used.
    #
    # Do this centrally so every caller is protected.
    # ------------------------------------------------------------------

    system_content = (
        "You must return the answer as valid JSON. "
        "The response must be a JSON object only.\n\n"
        + system_prompt.strip()
    )

    user_content = user_prompt.strip()

    messages = [
        {
            "role": "system",
            "content": system_content,
        },
        {
            "role": "user",
            "content": user_content,
        },
    ]

    response = llm_call(
        messages=messages,
        temperature=0.0,
        response_format={
            "type": "json_object"
        },
        max_tokens=1200,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    response = _clean_json_response(
        response
    )

    try:

        result = json.loads(
            response
        )

    except json.JSONDecodeError as e:

        raise ValueError(
            "LLM returned invalid JSON:\n"
            + response
        ) from e

    if not isinstance(
        result,
        dict,
    ):

        raise ValueError(
            "LLM JSON response must be an object:\n"
            + json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
            )
        )

    return result


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
    """
    Extract only the explicitly mentioned security group.

    Existence is validated deterministically in Python.
    """

    system_prompt = """
You extract the security group or role explicitly mentioned
in a natural-language Trino authorization rule.

Return ONLY this JSON object:

{
  "security_group": null
}

Rules:

1. Extract only an explicitly mentioned security group or role.

2. Do not invent a security group.

3. Do not infer a group from a resource.

4. Do not infer a group from an action.

5. Do not validate whether the group exists.

6. Python performs existence validation.

7. Preserve the requested group name.

8. If no security group can be identified, return null.

9. Return no fields other than "security_group".

Examples:

Rule:
"finance manager can select from finance"

Return:
{
  "security_group": "finance_manager"
}

Rule:
"analyst can read the sales schema"

Return:
{
  "security_group": "analyst"
}

Rule:
"users can read the finance schema"

Return:
{
  "security_group": null
}
"""

    result = _llm_json(
        system_prompt,
        (
            "Available security groups:\n"
            + json.dumps(
                security_groups,
                ensure_ascii=False,
                indent=2,
            )
            + "\n\nRule:\n"
            + rule
        ),
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    if set(result.keys()) != {
        "security_group"
    }:

        raise ValueError(
            "Security group extraction returned invalid JSON. "
            "Expected exactly: security_group. "
            f"Received: {json.dumps(result, ensure_ascii=False)}"
        )

    group = result.get(
        "security_group"
    )

    if group is None or group == "":

        return {
            "security_group": None,
            "existSecureGroup": False,
            "feedback": (
                "No security group could be identified "
                "in the request."
            ),
        }

    if not isinstance(group, str):

        raise ValueError(
            "The 'security_group' field must be a string or null."
        )

    group = group.strip()

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
            "Available security groups are: "
            + (
                ", ".join(
                    repr(x)
                    for x in security_groups
                )
                if security_groups
                else "none"
            )
            + "."
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
    """
    Extract only resources explicitly mentioned in the rule.

    The LLM performs the initial extraction.

    Python then performs a deterministic recovery step for table names:
    if the rule explicitly contains the name of an existing table but
    the LLM returned table=None, Python restores that table name.

    The LLM does NOT perform expansion.
    The LLM does NOT perform validation.
    """

    system_prompt = """
You extract the DATA RESOURCE explicitly mentioned in a
natural-language Trino authorization rule.

The authoritative hierarchy is:

catalog
  └── schema
        └── table
              └── column

Return ONLY this JSON object:

{
  "catalog": null,
  "schema": null,
  "table": null,
  "column": null
}

Rules:

1. Extract only resources explicitly mentioned in the rule.

2. Do not invent resource names.

3. Do not replace an explicitly requested resource with another
   resource.

4. Do not validate whether a resource exists.

5. Python performs validation.

6. Preserve resource names exactly as requested.

7. If a catalog is explicitly mentioned, return it.

8. If a schema is explicitly mentioned, return it.

9. If a table is explicitly mentioned, return it.

10. If a column is explicitly mentioned, return it.

11. If a level is not explicitly specified, return null.

12. If a schema is specified but no table is specified,
    table MUST be null.

13. If a catalog is specified but no schema is specified,
    schema MUST be null.

14. If the rule explicitly names a table, NEVER return null
    for table.

15. Expansion is performed deterministically by Python.

16. Return no fields other than:
    catalog, schema, table, column.

Examples:

Rule:
"The Finance Manager can update catalog iceberg, schema finance."

Return:
{
  "catalog": "iceberg",
  "schema": "finance",
  "table": null,
  "column": null
}

Rule:
"The Finance Manager can update the asset table in
catalog iceberg, schema finance."

Return:
{
  "catalog": "iceberg",
  "schema": "finance",
  "table": "asset",
  "column": null
}

Rule:
"The Analyst can select table employees in schema hr."

Return:
{
  "catalog": null,
  "schema": "hr",
  "table": "employees",
  "column": null
}

Rule:
"The Analyst can select salary from employees in schema hr."

Return:
{
  "catalog": null,
  "schema": "hr",
  "table": "employees",
  "column": "salary"
}
"""

    result = _llm_json(
        system_prompt,
        (
            "Data Mesh Structure:\n"
            + json.dumps(
                data_mesh_structure,
                ensure_ascii=False,
                indent=2,
            )
            + "\n\nRule:\n"
            + rule
        ),
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    if set(result.keys()) != RESOURCE_FIELDS:

        missing = RESOURCE_FIELDS - set(result.keys())
        extra = set(result.keys()) - RESOURCE_FIELDS

        raise ValueError(
            "Resource extraction returned invalid JSON. "
            f"Missing fields: {sorted(missing)}. "
            f"Unexpected fields: {sorted(extra)}. "
            f"Received: {json.dumps(result, ensure_ascii=False)}"
        )

    resource = {
        "catalog": result.get("catalog"),
        "schema": result.get("schema"),
        "table": result.get("table"),
        "column": result.get("column"),
    }

    for field, value in resource.items():

        if value is not None and not isinstance(value, str):
            raise ValueError(
                f"Resource field '{field}' must be "
                "a string or null."
            )

        if isinstance(value, str):

            value = value.strip()

            resource[field] = (
                value
                if value
                else None
            )

    # ========================================================================
    # DETERMINISTIC TABLE RECOVERY
    # ========================================================================
    #
    # The LLM sometimes returns:
    #
    #   catalog = iceberg
    #   schema  = finance
    #   table   = null
    #
    # even though the rule explicitly says:
    #
    #   "... asset table ..."
    #
    # We must not expand the whole schema in this situation.
    #
    # If the rule contains exactly one existing table name from the
    # authoritative Data Mesh, recover that table deterministically.
    #
    # This never invents a table.
    # ========================================================================

    if (
        resource["table"] is None
        and resource["schema"] is not None
    ):

        candidate_tables = []

        catalog_name = resource["catalog"]
        schema_name = resource["schema"]

        # --------------------------------------------------------------------
        # Use the authoritative normalized Data Mesh structure.
        # --------------------------------------------------------------------

        if catalog_name and schema_name:

            catalog = _find_catalog(
                data_mesh_structure,
                catalog_name,
            )

            schema = _find_schema(
                catalog,
                schema_name,
            )

            if schema is not None:

                table_names = _get_table_names(
                    schema
                )

                rule_lower = rule.lower()

                for table_name in table_names:

                    if not isinstance(
                        table_name,
                        str,
                    ):
                        continue

                    # Exact word occurrence.
                    #
                    # This avoids matching:
                    #
                    #   asset
                    #
                    # inside:
                    #
                    #   asset_history
                    #
                    # or:
                    #
                    #   assets
                    #
                    import re

                    pattern = (
                        r"\b"
                        + re.escape(
                            table_name.lower()
                        )
                        + r"\b"
                    )

                    if re.search(
                        pattern,
                        rule_lower,
                    ):
                        candidate_tables.append(
                            table_name
                        )

        # --------------------------------------------------------------------
        # Recover only when exactly one table is explicitly identifiable.
        # --------------------------------------------------------------------

        if len(candidate_tables) == 1:

            resource["table"] = candidate_tables[0]

        # --------------------------------------------------------------------
        # If multiple existing table names occur in the rule, do not guess.
        # --------------------------------------------------------------------

        elif len(candidate_tables) > 1:

            raise ValueError(
                "Multiple table names were explicitly identified "
                "in the rule and the resource extractor did not "
                "return a table. "
                "Identified tables: "
                + ", ".join(
                    repr(x)
                    for x in candidate_tables
                )
            )

    return resource

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
    """
    Extract intended Trino actions.

    The LLM may only propose actions from Available Actions.
    Python validates the result again.
    """

    system_prompt = """
You identify the intended Trino authorization operation or
operations from a natural-language rule.

Return ONLY:

{
  "requested_actions": [
    {
      "intent": "",
      "action": null
    }
  ]
}

Rules:

1. Do not invent actions.

2. The "action" MUST be one of the supplied Available Actions
   or null if no available action matches.

3. Python will validate the action again.

4. Map natural-language operations to the closest available
   Trino action.

5. Use these mappings when applicable:

   SELECT / READ / QUERY / RETRIEVE DATA
       -> SelectFromColumns

   INSERT
       -> InsertIntoTable

   UPDATE
       -> UpdateTableColumns

   DELETE
       -> DeleteFromTable

   CREATE TABLE
       -> CreateTable

   CREATE SCHEMA
       -> CreateSchema

   CREATE VIEW
       -> CreateView

   DROP TABLE
       -> DropTable

   DROP SCHEMA
       -> DropSchema

   DROP VIEW
       -> DropView

   ADD COLUMN
       -> AddColumn

   ALTER COLUMN
       -> AlterColumn

   DROP COLUMN
       -> DropColumn

   RENAME TABLE
       -> RenameTable

   RENAME COLUMN
       -> RenameColumn

   SHOW TABLES
       -> ShowTables

   SHOW SCHEMAS
       -> ShowSchemas

   SHOW COLUMNS
       -> ShowColumns

6. A request may contain multiple operations.

7. Do not return an action that is not present in
   Available Actions.

8. The "intent" field describes the operation identified
   in the natural-language rule.

9. If an operation cannot be mapped to an available action,
   return null for its action.

10. Return no fields other than:
    requested_actions, intent, action.
"""

    result = _llm_json(
        system_prompt,
        (
            "Available Actions:\n"
            + json.dumps(
                available_actions,
                ensure_ascii=False,
                indent=2,
            )
            + "\n\nRule:\n"
            + rule
        ),
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    if set(result.keys()) != {
        "requested_actions"
    }:

        raise ValueError(
            "Action extraction returned invalid JSON. "
            "Expected exactly 'requested_actions'. "
            f"Received: {json.dumps(result, ensure_ascii=False)}"
        )

    requested_actions = result.get(
        "requested_actions"
    )

    if not isinstance(
        requested_actions,
        list,
    ):

        raise ValueError(
            "'requested_actions' must be a list."
        )

    normalized = []

    for item in requested_actions:

        if not isinstance(item, dict):

            normalized.append(
                {
                    "intent": "",
                    "action": None,
                }
            )

            continue

        normalized.append(
            {
                "intent": item.get(
                    "intent",
                    "",
                ),
                "action": item.get(
                    "action"
                ),
            }
        )

    return normalized


##############################################################
# Normalize
################################################################
def _normalize_data_mesh_structure(data_mesh_structure):
    """
    Normalize the compact Data Mesh representation:

    {
        "iceberg": {
            "hr": {
                "employees": [
                    "employee_id",
                    "name"
                ]
            }
        }
    }

    into the canonical representation expected by the
    deterministic traversal functions:

    {
        "catalogs": [
            {
                "name": "iceberg",
                "schemas": [
                    {
                        "name": "hr",
                        "tables": [
                            {
                                "name": "employees",
                                "columns": [
                                    "employee_id",
                                    "name"
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }
    """

    if not isinstance(
        data_mesh_structure,
        dict,
    ):
        return {
            "catalogs": []
        }

    # Already normalized.
    if isinstance(
        data_mesh_structure.get("catalogs"),
        list,
    ):
        return data_mesh_structure

    catalogs = []

    for catalog_name, schemas_data in data_mesh_structure.items():

        if not isinstance(
            schemas_data,
            dict,
        ):
            continue

        schemas = []

        for schema_name, tables_data in schemas_data.items():

            if not isinstance(
                tables_data,
                dict,
            ):
                continue

            tables = []

            for table_name, columns_data in tables_data.items():

                columns = []

                if isinstance(
                    columns_data,
                    list,
                ):

                    for column in columns_data:

                        if isinstance(
                            column,
                            str,
                        ):
                            columns.append(
                                column
                            )

                        elif isinstance(
                            column,
                            dict,
                        ):

                            column_name = column.get(
                                "name"
                            )

                            if column_name:
                                columns.append(
                                    column_name
                                )

                tables.append(
                    {
                        "name": table_name,
                        "columns": columns,
                    }
                )

            schemas.append(
                {
                    "name": schema_name,
                    "tables": tables,
                }
            )

        catalogs.append(
            {
                "name": catalog_name,
                "schemas": schemas,
            }
        )

    return {
        "catalogs": catalogs
    }


# ============================================================================
# Final explanation
# ============================================================================

def _generate_final_explanation(
    rule,
    security_group_result,
    resource,
    expanded_resources,
    action_result,
    requested_actions,
    path_result,
    examples,
    is_local,
    chat_url=None,
    client=None,
    model=None,
):
    """
    Generate only the human-readable explanation.

    IMPORTANT:

    The returned llm_feedback is NOT trusted for validation.
    Deterministic validation is handled by Python.
    """

    system_prompt = """
You explain a Trino authorization request.

Return ONLY:

{
  "text": ""
}

Rules:

1. Describe the original request concisely.

2. Do not invent resources.

3. Do not invent security groups.

4. Do not invent actions.

5. Use only the supplied information.

6. Do not silently replace the requested resource.

7. Do not introduce "*" or wildcard resources.

8. If the resource was expanded, describe the actual
   catalog/schema/table resources supplied.

9. If validation failed, clearly state that the requested
   resource or action could not be validated.

10. Do not claim that a request is valid when the supplied
    validation result is invalid.

11. Return no fields other than "text".

12. Do not return markdown.
"""

    context = {
        "rule": rule,
        "security_group": security_group_result,
        "resource": resource,
        "expanded_resources": expanded_resources,
        "actions": {
            "requested": requested_actions,
            "validation": action_result,
        },
        "path_validation": path_result,
        "semantic_examples": examples,
    }

    result = _llm_json(
        system_prompt,
        json.dumps(
            context,
            ensure_ascii=False,
            indent=2,
        ),
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    if set(result.keys()) != {"text"}:

        raise ValueError(
            "Final explanation returned invalid JSON. "
            f"Received: {json.dumps(result, ensure_ascii=False)}"
        )

    text = result.get("text")

    if not isinstance(text, str):
        text = ""

    text = text.strip()

    if not text:
        text = rule

    return text


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
    """
    Interpret and validate a natural-language Trino
    authorization rule.

    Pipeline:

        Natural language
              |
              +--> semantic examples
              |
              +--> security group extraction
              |
              +--> resource extraction
              |
              +--> deterministic resource validation
              |
              +--> deterministic resource expansion
              |
              +--> action extraction
              |
              +--> deterministic action validation
              |
              +--> deterministic feedback
              |
              +--> final explanation

    The LLM never determines whether a resource exists.

    The LLM never expands resources.

    The LLM never determines whether an action exists.
    """

    if not isinstance(
        rule,
        str,
    ) or not rule.strip():

        raise ValueError(
            "The rule must be a non-empty string."
        )

    rule = rule.strip()

    # Normalize Data Mesh once.
    data_mesh_structure = _normalize_data_mesh_structure(
        data_mesh_structure
    )

    # =========================================================================
    # 0. Normalize authoritative inputs
    # =========================================================================

    security_groups = [
        group
        for group in (
            security_groups
            if isinstance(
                security_groups,
                list,
            )
            else []
        )
        if isinstance(group, str)
        and group.strip()
    ]

    available_actions = _normalize_available_actions(
        available_actions
    )

    # =========================================================================
    # 1. Retrieve semantic examples
    # =========================================================================

    examples = []

    if example_index:

        examples = find_best_examples(
            rule=rule,
            index=example_index,
            is_local=is_local,
            n=n,
            embedding_url=embedding_url,
            client=client,
            embedding_model=embedding_model,
        )

    # =========================================================================
    # 2. Extract security group
    # =========================================================================

    security_group_result = _extract_security_group(
        rule=rule,
        security_groups=security_groups,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    # =========================================================================
    # 3. Extract resource
    # =========================================================================

    resource = _extract_resource(
        rule=rule,
        data_mesh_structure=data_mesh_structure,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    # =========================================================================
    # 4. Deterministic Data Mesh validation
    # =========================================================================

    path_result = _validate_resource_path(
        resource=resource,
        data_mesh_structure=data_mesh_structure,
    )

    # =========================================================================
    # 5. Deterministic resource expansion
    #
    # NEVER expand an invalid resource.
    # NEVER generate "*".
    # =========================================================================

    expanded_resources = []

    if path_result["valid"]:

        expanded_resources = _expand_resource(
            resource=resource,
            data_mesh_structure=data_mesh_structure,
        )

    # =========================================================================
    # 6. Extract actions
    # =========================================================================

    requested_actions = _extract_actions(
        rule=rule,
        available_actions=available_actions,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    # =========================================================================
    # 7. Deterministic action validation
    # =========================================================================

    action_result = _validate_actions(
        requested_actions=requested_actions,
        available_actions=available_actions,
    )

    # =========================================================================
    # 8. Action existence
    # =========================================================================

    action_existence = _build_action_existence(
        requested_actions=requested_actions,
        available_actions=available_actions,
    )

    # =========================================================================
    # 9. Deterministic feedback
    # =========================================================================

    feedback = []

    if security_group_result.get(
        "feedback"
    ):

        feedback.append(
            security_group_result[
                "feedback"
            ]
        )

    if path_result.get(
        "feedback"
    ):

        feedback.append(
            path_result[
                "feedback"
            ]
        )

    if action_result.get(
        "feedback"
    ):

        feedback.append(
            action_result[
                "feedback"
            ]
        )

    # =========================================================================
    # 10. Additional deterministic resource feedback
    #
    # A syntactically valid resource that expands to zero resources
    # is also considered unresolved.
    # =========================================================================

    resource_was_requested = any(
        resource.get(field)
        for field in RESOURCE_FIELDS
    )

    if (
        path_result["valid"]
        and resource_was_requested
        and not expanded_resources
    ):

        feedback.append(
            "The requested resource path is valid syntactically, "
            "but it does not resolve to any concrete table or column "
            "in the Data Mesh Structure."
        )

    # =========================================================================
    # 11. Final explanation
    # =========================================================================

    text = _generate_final_explanation(
        rule=rule,
        security_group_result=security_group_result,
        resource=resource,
        expanded_resources=expanded_resources,
        action_result=action_result,
        requested_actions=requested_actions,
        path_result=path_result,
        examples=examples,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    # =========================================================================
    # 12. Only valid actions are returned as trinoActions
    # =========================================================================

    valid_trino_actions = []

    available_action_set = set(
        available_actions
    )

    for item in requested_actions:

        if not isinstance(item, dict):
            continue

        action = item.get(
            "action"
        )

        if action in available_action_set:

            valid_trino_actions.append(
                {
                    "intent": item.get(
                        "intent",
                        "",
                    ),
                    "action": action,
                }
            )

    # =========================================================================
    # 13. Return
    # =========================================================================

    return {
        "text": text,

        "existSecureGroup":
            security_group_result[
                "existSecureGroup"
            ],

        "pathExistOnDataMeshStructure":
            path_result[
                "valid"
            ],

        "actionExist":
            action_existence,

        "resource": {
            "catalogName":
                resource.get(
                    "catalog"
                ),

            "schemaName":
                resource.get(
                    "schema"
                ),

            "tableName":
                resource.get(
                    "table"
                ),

            "columnName":
                resource.get(
                    "column"
                ),
        },

        "expandedResources":
            expanded_resources,

        "trinoActions":
            valid_trino_actions,

        "llm_feedback":
            " ".join(
                feedback
            ),
    }
