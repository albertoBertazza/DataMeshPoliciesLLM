import json
import numpy as np

from LLM.Interface.embedding_call import embedding_call
from LLM.Interface.llm_call import llm_call


# ============================================================================
# Prompt
# ============================================================================

EXTRACT_SYSTEM_PROMPT_TEMPLATE = """
You are an authorization policy parser.

The user will describe an access rule in natural language.

Interpret the sentence as an authorization policy.

Your task:

1. Identify the subject (user or group).
2. Identify the resource scope.
3. Identify the requested user action.
4. Convert the requested user action into the required Trino authorization
   actions using the provided action mapping.
5. Detect whether the policy explicitly contains column masking.
6. Detect whether the policy explicitly contains row filtering.
7. Return only the required Trino authorization actions.

IMPORTANT:

- Return ONLY valid JSON.
- Never explain anything.
- Never output markdown.
- Never output ```json.
- Do not output any text before or after the JSON.

SUBJECT RULES:

- "subject_attribute" must be either "user" or "groups".
- "subject_value" must contain the exact user or group mentioned.
- Do not invent users or groups.

RESOURCE RULES:

- "resource_type" must be one of:
  "catalog", "schema", "table", "column".

- Extract only the resource explicitly mentioned or clearly defined
  by the user's rule.

- NEVER invent catalog, schema, table, or column names.

- NEVER use "*" as a resource value.

- NEVER use "*" for:
  - catalogName
  - schemaName
  - tableName
  - columnName

- Empty string "" means that the resource level is not specified.

RESOURCE HIERARCHY:

A catalog-level rule:

{
  "resource_type": "catalog",
  "resource_values": {
    "catalogName": "iceberg",
    "schemaName": "",
    "tableName": "",
    "columnName": ""
  }
}

A schema-level rule:

{
  "resource_type": "schema",
  "resource_values": {
    "catalogName": "iceberg",
    "schemaName": "finance",
    "tableName": "",
    "columnName": ""
  }
}

A table-level rule:

{
  "resource_type": "table",
  "resource_values": {
    "catalogName": "iceberg",
    "schemaName": "finance",
    "tableName": "employee_finance",
    "columnName": ""
  }
}

A column-level rule:

{
  "resource_type": "column",
  "resource_values": {
    "catalogName": "iceberg",
    "schemaName": "finance",
    "tableName": "employee_finance",
    "columnName": "salary"
  }
}

IMPORTANT:

If the user says:

"can SELECT from tables inside schema finance"

this is a SCHEMA-level permission.

Return:

{
  "resource_type": "schema",
  "resource_values": {
    "catalogName": "iceberg",
    "schemaName": "finance",
    "tableName": "",
    "columnName": ""
  }
}

Do NOT create a fake table name.

Do NOT use "*".

The meaning is:

"the permission applies to the schema and therefore to resources
inside that schema."

The actual tables covered by the schema permission will be resolved
later using the authoritative Data Mesh structure.

UNRESTRICTED ACCESS:

If the policy explicitly grants unrestricted access, do NOT use "*".

Instead return the broadest resource level that is actually stated.

For example:

"admin has access to all catalogs"

should return:

{
  "resource_type": "catalog",
  "resource_values": {
    "catalogName": "",
    "schemaName": "",
    "tableName": "",
    "columnName": ""
  }
}

If the request does not specify any concrete resource, leave all
resource values empty.

Do not invent resource names.

ACTION RULES:

- "trino_action" MUST contain only Trino authorization actions.
- Do not return SQL operations such as SELECT, INSERT, UPDATE, DELETE.
- Convert SQL operations using the supplied action mapping.
- If an operation requires multiple Trino permissions, return all required
  permissions.
- Do not invent actions.
- Every returned action MUST exist in the supplied action mapping.

IMPORTANT SELECT RULE:

For a normal SELECT/read request:

- Include the permissions required by the supplied action mapping.
- Do NOT add GetColumnMask unless column_mask is true.
- Do NOT add GetRowFilters unless row_filter is true.

COLUMN MASK RULES:

Set "column_mask": true ONLY if the policy explicitly says:

- a column is hidden
- a column is masked
- a column value must be replaced
- a column value must be redacted
- a masking expression is provided

Normal SELECT permission MUST NOT create column masking.

ROW FILTER RULES:

Set "row_filter": true ONLY if the policy explicitly says:

- only specific rows are visible
- rows must be filtered
- a predicate limits returned rows
- a condition limits returned rows

Normal SELECT permission MUST NOT create row filtering.

If no explicit masking/filtering exists:

"column_mask": false
"row_filter": false

Never add GetColumnMask only because SELECT normally uses it.

Never add GetRowFilters only because SELECT normally uses it.

If column_mask is true, GetColumnMask may be included.

If row_filter is true, GetRowFilters may be included.

USER ACTION TO TRINO AUTHORIZATION MAPPING:

__VALID_ACTIONS__

OUTPUT FORMAT:

{
  "subject_attribute": "groups",
  "subject_value": "",
  "resource_type": "schema",
  "resource_values": {
    "catalogName": "",
    "schemaName": "",
    "tableName": "",
    "columnName": ""
  },
  "trino_action": [],
  "column_mask": false,
  "row_filter": false
}

If column_mask is true, optionally include:

"column_mask_policy": {
  "expression": ""
}

If row_filter is true, optionally include:

"row_filter_policy": {
  "expression": ""
}

RELEVANT EXAMPLES:

__EXAMPLES__
"""


# ============================================================================
# Similarity / Example retrieval
# ============================================================================

def retrieve_examples(
    rule,
    extraction_indexes,
    is_local,
    n=3,
    embedding_url=None,
    client=None,
    embedding_model=None
):

    if not extraction_indexes:
        return []

    texts = [
        x["input"]["extraction"]
        for x in extraction_indexes
    ]

    example_embeddings = np.array(
        [
            embedding_call(
                text=text,
                is_local=is_local,
                embedding_url=embedding_url,
                client=client,
                embedding_model=embedding_model
            )
            for text in texts
        ]
    )

    rule_embedding = embedding_call(
        text=rule,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model
    )

    example_norms = np.linalg.norm(
        example_embeddings,
        axis=1,
        keepdims=True
    )

    example_norms[example_norms == 0] = 1

    example_embeddings = (
        example_embeddings / example_norms
    )

    rule_norm = np.linalg.norm(
        rule_embedding
    )

    if rule_norm == 0:
        rule_norm = 1

    rule_embedding = (
        rule_embedding / rule_norm
    )

    scores = example_embeddings @ rule_embedding

    best_indexes = np.argsort(scores)[::-1][:n]

    return [
        extraction_indexes[i]
        for i in best_indexes
    ]


# ============================================================================
# Format examples
# ============================================================================

def format_examples(examples):

    if not examples:
        return "No relevant examples available."

    result = []

    for ex in examples:

        output = ex["output"]

        # ------------------------------------------------------------
        # Defensive cleanup of old training examples.
        #
        # This is important if your index still contains examples
        # generated with "*".
        # ------------------------------------------------------------



        result.append(
            f"""
Input:
{ex['input']['extraction']}

Output:
{json.dumps(
    output,
    indent=2,
    ensure_ascii=False
)}
"""
        )

    return "\n".join(result)


# ============================================================================
# Build system prompt
# ============================================================================

def get_extract_system_prompt(
    check_for_action,
    examples
):

    prompt = EXTRACT_SYSTEM_PROMPT_TEMPLATE

    prompt = prompt.replace(
        "__VALID_ACTIONS__",
        json.dumps(
            check_for_action,
            indent=2,
            ensure_ascii=False
        )
    )

    prompt = prompt.replace(
        "__EXAMPLES__",
        examples
    )

    return prompt


# ============================================================================
# LLM extraction
# ============================================================================

def llm_extract(
    rule,
    check_for_action,
    extraction_indexes,
    is_local,
    chat_url=None,
    embedding_url=None,
    client=None,
    model=None,
    embedding_model=None
):

    try:

        examples = retrieve_examples(
            rule,
            extraction_indexes,
            is_local,
            n=3,
            embedding_url=embedding_url,
            client=client,
            embedding_model=embedding_model
        )

    except Exception as e:

        print(
            "Failed to retrieve_examples in llm_extract:",
            e
        )

        return None

    formatted_examples = format_examples(
        examples
    )

    system_prompt = get_extract_system_prompt(
        check_for_action,
        formatted_examples
    )

    user_prompt = rule

    try:

        response = llm_call(
            prompt=user_prompt,
            system_prompt=system_prompt,
            response_format={
                "type": "json_object"
            },
            temperature=0.0,
            max_tokens=1200,
            is_local=is_local,
            chat_url=chat_url,
            client=client,
            model=model
        )

    except Exception as e:

        print(
            "Failed to llm_call in llm_extract:",
            e
        )

        return None

    if response is None:
        return None

    return response.strip()


# ============================================================================
# JSON cleanup
# ============================================================================

def _clean_json_response(raw):

    if raw is None:
        raise ValueError(
            "LLM returned None."
        )

    response = raw.strip()

    if response.startswith("```"):

        lines = response.splitlines()

        if lines:
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        response = "\n".join(
            lines
        ).strip()

    if not response.startswith("{"):

        start = response.find("{")
        end = response.rfind("}")

        if start != -1 and end != -1 and end > start:
            response = response[
                start:end + 1
            ]

    return response


# ============================================================================
# Normalize extraction
# ============================================================================

def _normalize_extraction(
    result,
    check_for_action
):

    if not isinstance(result, dict):
        raise ValueError(
            "LLM extraction result is not a JSON object."
        )

    result.setdefault(
        "subject_attribute",
        ""
    )

    result.setdefault(
        "subject_value",
        ""
    )

    result.setdefault(
        "resource_type",
        ""
    )

    result.setdefault(
        "resource_values",
        {}
    )

    result.setdefault(
        "trino_action",
        []
    )

    result.setdefault(
        "column_mask",
        False
    )

    result.setdefault(
        "row_filter",
        False
    )

    # ------------------------------------------------------------------------
    # Resource values
    # ------------------------------------------------------------------------

    resource_values = result.get(
        "resource_values"
    )

    if not isinstance(
        resource_values,
        dict
    ):
        resource_values = {}

    resource_values.setdefault(
        "catalogName",
        ""
    )

    resource_values.setdefault(
        "schemaName",
        ""
    )

    resource_values.setdefault(
        "tableName",
        ""
    )

    resource_values.setdefault(
        "columnName",
        ""
    )

    # ------------------------------------------------------------------------
    # HARD RULE:
    #
    # Never allow "*" to survive extraction.
    #
    # If an old/local model still produces "*", convert it to the
    # unspecified value "".
    # ------------------------------------------------------------------------

    for key in (
        "catalogName",
        "schemaName",
        "tableName",
        "columnName"
    ):

        if resource_values.get(key) == "*":

            resource_values[key] = ""

    result[
        "resource_values"
    ] = resource_values

    # ------------------------------------------------------------------------
    # Normalize actions
    # ------------------------------------------------------------------------

    actions = result.get(
        "trino_action"
    )

    if not isinstance(
        actions,
        list
    ):
        actions = []

    # Never allow "*" as an action either.
    actions = [
        action
        for action in actions
        if action != "*"
    ]

    result[
        "trino_action"
    ] = actions

    # ------------------------------------------------------------------------
    # Remove mask/filter permissions when not requested
    # ------------------------------------------------------------------------

    if not result["column_mask"]:

        result["trino_action"] = [
            action
            for action in result["trino_action"]
            if action != "GetColumnMask"
        ]

    if not result["row_filter"]:

        result["trino_action"] = [
            action
            for action in result["trino_action"]
            if action != "GetRowFilters"
        ]

    # ------------------------------------------------------------------------
    # Validate subject
    # ------------------------------------------------------------------------

    if result["subject_attribute"] not in (
        "user",
        "groups"
    ):

        raise ValueError(
            "Invalid subject_attribute: "
            + repr(
                result["subject_attribute"]
            )
        )

    # ------------------------------------------------------------------------
    # Validate resource type
    # ------------------------------------------------------------------------

    if result["resource_type"] not in (
        "catalog",
        "schema",
        "table",
        "column"
    ):

        raise ValueError(
            "Invalid resource_type: "
            + repr(
                result["resource_type"]
            )
        )

    # ------------------------------------------------------------------------
    # Validate resource hierarchy
    # ------------------------------------------------------------------------

    resource_type = result["resource_type"]

    values = result["resource_values"]

    if resource_type == "catalog":

        if not values["catalogName"]:
            raise ValueError(
                "Catalog resource requires catalogName."
            )

        values["schemaName"] = ""
        values["tableName"] = ""
        values["columnName"] = ""

    elif resource_type == "schema":

        if not values["schemaName"]:
            raise ValueError(
                "Schema resource requires schemaName."
            )

        if not values["catalogName"]:
            raise ValueError(
                "Schema resource requires catalogName."
            )

        values["tableName"] = ""
        values["columnName"] = ""

    elif resource_type == "table":

        if not values["tableName"]:
            raise ValueError(
                "Table resource requires tableName."
            )

        if not values["schemaName"]:
            raise ValueError(
                "Table resource requires schemaName."
            )

        if not values["catalogName"]:
            raise ValueError(
                "Table resource requires catalogName."
            )

        values["columnName"] = ""

    elif resource_type == "column":

        if not values["columnName"]:
            raise ValueError(
                "Column resource requires columnName."
            )

        if not values["tableName"]:
            raise ValueError(
                "Column resource requires tableName."
            )

        if not values["schemaName"]:
            raise ValueError(
                "Column resource requires schemaName."
            )

        if not values["catalogName"]:
            raise ValueError(
                "Column resource requires catalogName."
            )

    # ------------------------------------------------------------------------
    # Validate actions
    # ------------------------------------------------------------------------

    valid_trino_actions = {
        permission
        for permissions in check_for_action.values()
        for permission in permissions
    }

    for action in result["trino_action"]:

        if action not in valid_trino_actions:
            raise ValueError(
                f"Invalid Trino authorization action: "
                f"{action!r}"
            )

    # ------------------------------------------------------------------------
    # Mask policy
    # ------------------------------------------------------------------------

    if result["column_mask"]:

        if "column_mask_policy" not in result:

            result[
                "column_mask_policy"
            ] = {
                "expression": ""
            }

    else:

        result.pop(
            "column_mask_policy",
            None
        )

    # ------------------------------------------------------------------------
    # Row filter policy
    # ------------------------------------------------------------------------

    if result["row_filter"]:

        if "row_filter_policy" not in result:

            result[
                "row_filter_policy"
            ] = {
                "expression": ""
            }

    else:

        result.pop(
            "row_filter_policy",
            None
        )

    return result


# ============================================================================
# Main extraction function
# ============================================================================

def extract_entities(
    rule,
    extraction_indexes,
    check_for_action,
    is_local,
    chat_url=None,
    embedding_url=None,
    client=None,
    model=None,
    embedding_model=None
):

    try:

        raw = llm_extract(
            rule=rule,
            check_for_action=check_for_action,
            extraction_indexes=extraction_indexes,
            is_local=is_local,
            chat_url=chat_url,
            embedding_url=embedding_url,
            client=client,
            model=model,
            embedding_model=embedding_model
        )

    except Exception as e:

        print(
            "Failed to llm_extract in extract_entities:",
            e
        )

        return None

    if raw is None:

        print(
            "Extraction failed: LLM returned no response."
        )

        return None


    # ------------------------------------------------------------------------
    # Clean JSON
    # ------------------------------------------------------------------------

    try:

        cleaned = _clean_json_response(
            raw
        )

        result = json.loads(
            cleaned
        )

    except Exception as e:

        print("Extraction failed: invalid JSON:", raw)

        print(
            "JSON error:",
            e
        )

        return None

    # ------------------------------------------------------------------------
    # Normalize and validate
    # ------------------------------------------------------------------------

    try:

        result = _normalize_extraction(
            result,
            check_for_action
        )

    except Exception as e:

        print(
            "Extraction failed during validation:",
            e
        )

        return None

    print("Extracted:\n ", json.dumps(
            result,
            indent=2
        ))
    return result
