import json
import traceback
import numpy as np

from copy import deepcopy

from LLM.Interface.llm_call import llm_call
from LLM.Interface.embedding_call import embedding_call


# ============================================================================
# Operation -> Trino input resource shape
# ============================================================================

OPERATION_RESOURCE_SHAPES = {

    "ExecuteQuery":
        "input.action.operation only. No resource is present.",

    "AccessCatalog":
        "input.action.resource.catalog.name",

    "AccessSchema":
        "input.action.resource.schema.catalogName and schemaName",

    "SelectFromColumns":
        "input.action.resource.table.catalogName/schemaName/tableName "
        "OR input.action.resource.column.catalogName/schemaName/tableName/columnName",

    "GetColumnMask":
        "input.action.filterResources[].column."
        "catalogName/schemaName/tableName/columnName. "
        "Only generate masks when column_mask is true.",

    "GetRowFilters":
        "input.action.resource.table."
        "catalogName/schemaName/tableName. "
        "Only generate filters when row_filter is true.",

    "InsertIntoTable":
        "input.action.resource.table."
        "catalogName/schemaName/tableName",

    "UpdateTableColumns":
        "input.action.resource.table."
        "catalogName/schemaName/tableName",

    "DeleteFromTable":
        "input.action.resource.table."
        "catalogName/schemaName/tableName",
}


# ============================================================================
# Prompt
# ============================================================================

GENERATE_REGO_SYSTEM_PROMPT_TEMPLATE = """
You are an expert OPA Rego author generating Trino authorization rules.

You receive an extracted authorization policy.

Extraction format:

{extraction_structure}

Trino input examples:

{input_structure}

Operation resource mapping:

{operation_resource_shapes}

Reference Rego examples:

{example_rego}

The following base policy is always present:

default allow := false
default batchColumnMasks := []
default rowFilters := []

Generated output is merged into this base policy.

Never generate these default rules.


IMPORTANT GENERATION RULES:

1. Generate ONLY Rego rule bodies.

DO NOT generate:
- package
- imports
- default rules


2. Always generate the subject helper:

is_<subject> if {
    ...
}


3. Generate allow rules only for these authorization operations:

- ExecuteQuery
- AccessCatalog
- AccessSchema
- SelectFromColumns
- InsertIntoTable
- UpdateTableColumns
- DeleteFromTable


4. GetColumnMask and GetRowFilters are OPTIONAL.

Generate them ONLY when:

column_mask == true

or:

row_filter == true

Never create masks or filters merely because Trino may call those endpoints.


5. Column masking.

If:

"column_mask": true

generate:

batchColumnMasks contains result if {
    ...
    result := {
        "column": column,
        "mask": "<expression>"
    }
}

Use ONLY the supplied masking expression.

If:

"column_mask": false

DO NOT generate batchColumnMasks rules.


6. Row filtering.

If:

"row_filter": true

generate:

rowFilters contains filter if {
    ...
    filter := {
        "expression": "<expression>"
    }
}

Use ONLY the supplied filtering expression.

If:

"row_filter": false

DO NOT generate rowFilters rules.


7. Never invent:

- users
- groups
- catalogs
- schemas
- tables
- columns
- masks
- filters
- operations
- expressions


8. Resource scope must be respected.

For example:

"finance manager can select from table inside schema finance"

means that the subject has SELECT authorization for tables
inside the finance schema.

Do not invent a table name.

Do not invent a column.

Do not create column masking.

Do not create row filtering.


9. Use exact Trino input paths.

10. Return ONLY valid Rego body.

No markdown fences.
No explanations.
"""


# ============================================================================
# Build Trino input examples
# ============================================================================

def build_input_examples(
    input_structure,
    extracted_entity
):
    """
    Build minimal Trino examples required by the extracted operations.
    """

    if not isinstance(extracted_entity, dict):
        raise ValueError(
            "extracted_entity must be a dictionary"
        )

    actions = extracted_entity.get(
        "trino_permission",
        []
    )

    if not isinstance(actions, list):
        raise ValueError(
            "extracted_entity['trino_permission'] must be a list"
        )

    values = extracted_entity.get(
        "resource_values",
        {}
    )

    if not isinstance(values, dict):
        values = {}

    resource_type = extracted_entity.get(
        "resource_type"
    )

    subject_attribute = extracted_entity.get(
        "subject_attribute"
    )

    subject_value = extracted_entity.get(
        "subject_value"
    )

    examples = []

    for operation in actions:

        example = deepcopy(
            input_structure
        )

        if not isinstance(example, dict):
            raise ValueError(
                "input_structure must be a dictionary"
            )

        # ------------------------------------------------------------
        # Identity
        # ------------------------------------------------------------

        context = example.setdefault(
            "context",
            {}
        )

        identity = context.setdefault(
            "identity",
            {}
        )

        if subject_attribute == "groups":

            identity["groups"] = [
                subject_value
            ]

            identity["user"] = "<any-user>"

        elif subject_attribute == "user":

            identity["user"] = subject_value
            identity["groups"] = []

        else:

            raise ValueError(
                f"Unsupported subject_attribute: "
                f"{subject_attribute}"
            )

        # ------------------------------------------------------------
        # Action
        # ------------------------------------------------------------

        action = example.setdefault(
            "action",
            {}
        )

        action["operation"] = operation

        action.pop(
            "resource",
            None
        )

        action.pop(
            "filterResources",
            None
        )

        # ------------------------------------------------------------
        # ExecuteQuery
        # ------------------------------------------------------------

        if operation == "ExecuteQuery":

            pass

        # ------------------------------------------------------------
        # AccessCatalog
        # ------------------------------------------------------------

        elif operation == "AccessCatalog":

            action["resource"] = {
                "catalog": {
                    "name": values.get(
                        "catalogName"
                    )
                }
            }

        # ------------------------------------------------------------
        # AccessSchema
        # ------------------------------------------------------------

        elif operation == "AccessSchema":

            action["resource"] = {
                "schema": {
                    "catalogName": values.get(
                        "catalogName"
                    ),
                    "schemaName": values.get(
                        "schemaName"
                    )
                }
            }

        # ------------------------------------------------------------
        # SelectFromColumns
        # ------------------------------------------------------------

        elif operation == "SelectFromColumns":

            if resource_type == "column":

                action["resource"] = {
                    "column": {
                        "catalogName": values.get(
                            "catalogName"
                        ),
                        "schemaName": values.get(
                            "schemaName"
                        ),
                        "tableName": values.get(
                            "tableName"
                        ),
                        "columnName": values.get(
                            "columnName"
                        )
                    }
                }

            else:

                action["resource"] = {
                    "table": {
                        "catalogName": values.get(
                            "catalogName"
                        ),
                        "schemaName": values.get(
                            "schemaName"
                        ),
                        "tableName": values.get(
                            "tableName"
                        )
                    }
                }

        # ------------------------------------------------------------
        # GetColumnMask
        # ------------------------------------------------------------

        elif operation == "GetColumnMask":

            if (
                extracted_entity.get(
                    "column_mask",
                    False
                ) is not True
            ):
                continue

            if not values.get("columnName"):
                continue

            action["filterResources"] = [
                {
                    "column": {
                        "catalogName": values.get(
                            "catalogName"
                        ),
                        "schemaName": values.get(
                            "schemaName"
                        ),
                        "tableName": values.get(
                            "tableName"
                        ),
                        "columnName": values.get(
                            "columnName"
                        ),
                        "columnType": "varchar"
                    }
                }
            ]

        # ------------------------------------------------------------
        # GetRowFilters
        # ------------------------------------------------------------

        elif operation == "GetRowFilters":

            if (
                extracted_entity.get(
                    "row_filter",
                    False
                ) is not True
            ):
                continue

            action["resource"] = {
                "table": {
                    "catalogName": values.get(
                        "catalogName"
                    ),
                    "schemaName": values.get(
                        "schemaName"
                    ),
                    "tableName": values.get(
                        "tableName"
                    )
                }
            }

        # ------------------------------------------------------------
        # Table operations
        # ------------------------------------------------------------

        elif operation in {
            "InsertIntoTable",
            "UpdateTableColumns",
            "DeleteFromTable"
        }:

            action["resource"] = {
                "table": {
                    "catalogName": values.get(
                        "catalogName"
                    ),
                    "schemaName": values.get(
                        "schemaName"
                    ),
                    "tableName": values.get(
                        "tableName"
                    )
                }
            }

        else:

            raise ValueError(
                f"Unsupported operation: {operation}"
            )

        examples.append(
            example
        )

    return examples


# ============================================================================
# Prompt construction
# ============================================================================

def get_generate_rego_system_prompt(
    example_rego,
    input_structure,
    extracted_entity
):

    extraction_structure = {
        "subject_attribute": "user | groups",
        "subject_value": "",
        "resource_type": "catalog | schema | table | column",
        "resource_values": {
            "catalogName": "",
            "schemaName": "",
            "tableName": "",
            "columnName": ""
        },
        "trino_permission": [],
        "column_mask": False,
        "row_filter": False,
        "column_mask_policy": {
            "expression": ""
        },
        "row_filter_policy": {
            "expression": ""
        }
    }

    input_examples = build_input_examples(
        input_structure,
        extracted_entity
    )

    prompt = GENERATE_REGO_SYSTEM_PROMPT_TEMPLATE

    # IMPORTANT:
    # Do not use .format() because Rego examples contain { }.

    prompt = prompt.replace(
        "{extraction_structure}",
        json.dumps(
            extraction_structure,
            indent=2
        )
    )

    prompt = prompt.replace(
        "{input_structure}",
        json.dumps(
            input_examples,
            indent=2
        )
    )

    prompt = prompt.replace(
        "{operation_resource_shapes}",
        json.dumps(
            OPERATION_RESOURCE_SHAPES,
            indent=2
        )
    )

    prompt = prompt.replace(
        "{example_rego}",
        example_rego or ""
    )

    return prompt


# ============================================================================
# Cosine similarity
# ============================================================================

def cosine_similarity(a, b):

    a = np.asarray(a)
    b = np.asarray(b)

    denominator = (
        np.linalg.norm(a) *
        np.linalg.norm(b)
    )

    if denominator == 0:
        return 0.0

    return float(
        np.dot(a, b) / denominator
    )


# ============================================================================
# Find best Rego examples
# ============================================================================

def find_best_rego_examples(
    extracted_entity,
    example_rego,
    is_local,
    n=3,
    embedding_url=None,
    client=None,
    embedding_model=None
):

    if not isinstance(
        extracted_entity,
        dict
    ):
        raise ValueError(
            "extracted_entity is not a dictionary"
        )

    if not example_rego:
        return []

    requested_operations = set(
        extracted_entity.get(
            "trino_permission",
            []
        )
    )

    compatible_examples = []

    # ------------------------------------------------------------
    # Filter malformed examples safely
    # ------------------------------------------------------------

    for index, ex in enumerate(
        example_rego
    ):

        if not isinstance(
            ex,
            dict
        ):
            print(
                f"[WARNING] Skipping example {index}: "
                f"not a dictionary"
            )
            continue

        input_data = ex.get(
            "input"
        )

        if not isinstance(
            input_data,
            dict
        ):
            print(
                f"[WARNING] Skipping example {index}: "
                f"input is missing or invalid"
            )
            continue

        extraction = input_data.get(
            "extraction"
        )

        if not isinstance(
            extraction,
            dict
        ):
            print(
                f"[WARNING] Skipping example {index}: "
                f"extraction is missing or invalid"
            )
            continue

        example_operations = set(
            extraction.get(
                "trino_permission",
                []
            )
        )

        if not requested_operations.intersection(
            example_operations
        ):
            continue

        same_mask = (
            extracted_entity.get(
                "column_mask",
                False
            )
            ==
            extraction.get(
                "column_mask",
                False
            )
        )

        same_filter = (
            extracted_entity.get(
                "row_filter",
                False
            )
            ==
            extraction.get(
                "row_filter",
                False
            )
        )

        if same_mask and same_filter:
            compatible_examples.append(
                ex
            )

    # ------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------

    if not compatible_examples:

        compatible_examples = [
            ex
            for ex in example_rego
            if isinstance(ex, dict)
            and isinstance(
                ex.get("input"),
                dict
            )
        ]

    if not compatible_examples:
        return []

    # ------------------------------------------------------------
    # Build query embedding
    # ------------------------------------------------------------

    query = json.dumps(
        extracted_entity,
        sort_keys=True,
        indent=2
    )

    query_embedding = embedding_call(
        text=query,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model
    )

    # ------------------------------------------------------------
    # Rank examples
    # ------------------------------------------------------------

    ranked = []

    for index, ex in enumerate(
        compatible_examples
    ):

        embedding = ex.get(
            "embedding"
        )

        if embedding is None:

            print(
                f"[WARNING] Example {index} has no embedding. "
                f"Skipping."
            )

            continue

        try:

            score = cosine_similarity(
                query_embedding,
                embedding
            )

            ranked.append(
                (
                    score,
                    ex
                )
            )

        except Exception as e:

            print(
                f"[WARNING] Could not calculate similarity "
                f"for example {index}: {e}"
            )

    ranked.sort(
        key=lambda x: x[0],
        reverse=True
    )

    return [
        ex
        for _, ex in ranked[:n]
    ]


# ============================================================================
# Local / OpenAI LLM generation
# ============================================================================

def llm_generate_rego(
    extracted_entity,
    example_rego,
    input_structure,
    is_local,
    chat_url=None,
    client=None,
    model=None
):

    system_prompt = get_generate_rego_system_prompt(
        example_rego=example_rego,
        input_structure=input_structure,
        extracted_entity=extracted_entity
    )

    messages = [
        {
            "role": "system",
            "content": system_prompt
        },
        {
            "role": "user",
            "content": json.dumps(
                extracted_entity,
                indent=2
            )
        }
    ]

    # IMPORTANT:
    # Your llm_call() expects ONE prompt string.
    prompt = json.dumps(
        messages,
        indent=2
    )

    print(
        "\n\t[Rego generation prompt]"
    )

    print(
        "\n\t[Calling LLM...]"
    )

    response = llm_call(
        prompt,
        temperature=0.0,
        max_tokens=2000,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model
    )

    if response is None:
        raise ValueError(
            "LLM returned None"
        )

    return response.strip()


# ============================================================================
# Clean Rego output
# ============================================================================

def clean_rego_output(raw):

    if raw is None:
        return ""

    raw = raw.strip()

    if raw.startswith(
        "```"
    ):

        lines = raw.splitlines()

        if (
            lines
            and lines[0].strip().startswith(
                "```"
            )
        ):
            lines = lines[1:]

        if (
            lines
            and lines[-1].strip().startswith(
                "```"
            )
        ):
            lines = lines[:-1]

        raw = "\n".join(
            lines
        ).strip()

    return raw


# ============================================================================
# Main generation function
# ============================================================================

def generate_rego_policy(
    extracted_entity,
    example_rego,
    input_structure,
    is_local,
    chat_url=None,
    embedding_url=None,
    client=None,
    model=None,
    embedding_model=None
):

    try:

        print(
            "\n\t[Selecting Rego examples...]"
        )

        examples = find_best_rego_examples(
            extracted_entity=extracted_entity,
            example_rego=example_rego,
            is_local=is_local,
            n=3,
            embedding_url=embedding_url,
            client=client,
            embedding_model=embedding_model
        )

        print(
            f"\tSelected {len(examples)} Rego examples."
        )

        # ------------------------------------------------------------
        # Safely extract example outputs
        # ------------------------------------------------------------

        example_outputs = []

        for index, ex in enumerate(
            examples
        ):

            if not isinstance(
                ex,
                dict
            ):
                continue

            output = ex.get(
                "output"
            )

            if output is None:
                continue

            if not isinstance(
                output,
                str
            ):
                output = json.dumps(
                    output,
                    indent=2
                )

            example_outputs.append(
                output
            )

        example_text = "\n\n".join(
            example_outputs
        )

        # ------------------------------------------------------------
        # Generate
        # ------------------------------------------------------------

        print(
            "\n[Generating Rego with LLM...]"
        )

        raw = llm_generate_rego(
            extracted_entity=extracted_entity,
            example_rego=example_text,
            input_structure=input_structure,
            is_local=is_local,
            chat_url=chat_url,
            client=client,
            model=model
        )

        if not raw:
            raise ValueError(
                "LLM returned an empty Rego response"
            )

        policy = clean_rego_output(
            raw
        )

        print(
            "\n[RAW REGO OUTPUT]"
        )

        print(
            policy
        )

        return policy

    except Exception as e:

        print(
            "\nFailed generate_rego_policy:"
        )

        print(
            repr(e)
        )

        print(
            "\nFull traceback:"
        )

        traceback.print_exc()

        raise