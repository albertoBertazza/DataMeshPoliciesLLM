import json
from LLM.Interface.llm_call import llm_call
import numpy as np
from LLM.Interface.embedding_call import embedding_call
from copy import deepcopy


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
        "input.action.filterResources[].column.catalogName/schemaName/tableName/columnName. "
        "Only generate masks if the extracted policy explicitly contains column masking.",

    "GetRowFilters":
        "input.action.resource.table.catalogName/schemaName/tableName. "
        "Only generate filters if the extracted policy explicitly contains row filtering.",

    "InsertIntoTable":
        "input.action.resource.table.catalogName/schemaName/tableName",

    "UpdateTableColumns":
        "input.action.resource.table.catalogName/schemaName/tableName",

    "DeleteFromTable":
        "input.action.resource.table.catalogName/schemaName/tableName"
}


GENERATE_REGO_SYSTEM_PROMPT_TEMPLATE = """
You are an expert OPA Rego author generating Trino authorization rules.

You receive an extracted authorization policy.

Extraction format:

{extraction_structure}

Trino input format:

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

1. Generate ONLY Rego body.
Do not generate:
- package
- imports
- default rules


2. Always generate:

is_<subject> if {
    ...
}


3. Generate allow rules ONLY for authorization operations:

- ExecuteQuery
- AccessCatalog
- AccessSchema
- SelectFromColumns
- InsertIntoTable
- UpdateTableColumns
- DeleteFromTable


4. GetColumnMask and GetRowFilters are OPTIONAL.

Generate them ONLY when:
- the extracted policy explicitly requests masking/filtering
- the extracted resource is actually restricted


Never create:

batchColumnMasks

or

rowFilters

just because Trino called the endpoint.


Trino may call GetColumnMask and GetRowFilters even when no policy exists.
In that case return nothing for those operations.

5. Column masking and row filtering:

The extraction may contain:

"column_mask": true
"column_mask_policy": {
    "expression": "..."
}

"row_filter": true
"row_filter_policy": {
    "expression": "..."
}


If column_mask == true:

Generate:

batchColumnMasks contains result if {
    ...
    result := {
        "column": column,
        "mask": "<expression>"
    }
}


If row_filter == true:

Generate:

rowFilters contains filter if {
    ...
    filter := {
        "expression": "<expression>"
    }
}


If column_mask == false:
DO NOT generate batchColumnMasks.


If row_filter == false:
DO NOT generate rowFilters.


Never invent policies.
Use only expressions provided by extraction.

6. Operation mapping:

SelectFromColumns:
    allow if {}


GetColumnMask:
    batchColumnMasks contains result if {}


GetRowFilters:
    rowFilters contains result if {}


7. Never use:

batchColumnMasks[x] if

rowFilters[x] if


8. Never invent:
- columns
- filters
- masks
- operations


9. If the rule says:

"finance manager can select all tables inside finance schema"

generate schema/table authorization.

Do NOT generate:
- column masks
- row filters
- column restrictions


10. Use exact Trino input paths.

"""


def build_input_examples(input_structure, extracted_entity):
    """
    Build minimal Trino examples.
    Only include resources required by the operation.
    """

    examples = []

    actions = extracted_entity["trino_action"]

    values = extracted_entity["resource_values"]
    resource_type = extracted_entity["resource_type"]

    subject_attribute = extracted_entity["subject_attribute"]
    subject_value = extracted_entity["subject_value"]


    for operation in actions:

        example = deepcopy(input_structure)


        # identity

        if subject_attribute == "groups":

            example["context"]["identity"]["groups"] = [
                subject_value
            ]

            example["context"]["identity"]["user"] = "<any-user>"


        elif subject_attribute == "user":

            example["context"]["identity"]["user"] = subject_value
            example["context"]["identity"]["groups"] = []


        example["action"]["operation"] = operation


        example["action"].pop(
            "resource",
            None
        )

        example["action"].pop(
            "filterResources",
            None
        )


        # ExecuteQuery

        if operation == "ExecuteQuery":

            pass


        # AccessCatalog

        elif operation == "AccessCatalog":

            example["action"]["resource"] = {
                "catalog": {
                    "name": values["catalogName"]
                }
            }


        # AccessSchema

        elif operation == "AccessSchema":

            example["action"]["resource"] = {
                "schema": {
                    "catalogName": values["catalogName"],
                    "schemaName": values["schemaName"]
                }
            }


        # SelectFromColumns

        elif operation == "SelectFromColumns":

            if resource_type == "column":

                example["action"]["resource"] = {
                    "column": {
                        "catalogName": values["catalogName"],
                        "schemaName": values["schemaName"],
                        "tableName": values["tableName"],
                        "columnName": values["columnName"]
                    }
                }

            else:

                example["action"]["resource"] = {
                    "table": {
                        "catalogName": values["catalogName"],
                        "schemaName": values["schemaName"],
                        "tableName": values["tableName"]
                    }
                }


        # GetColumnMask

        elif operation == "GetColumnMask":

            if (

                    extracted_entity.get("column_mask") is True

                    and "columnName" in values

            ):

                example["action"]["filterResources"] = [

                    {

                        "column": {

                            "catalogName": values["catalogName"],

                            "schemaName": values["schemaName"],

                            "tableName": values["tableName"],

                            "columnName": values["columnName"],

                            "columnType": "varchar"

                        }

                    }

                ]


            else:

                continue



        # GetRowFilters

        elif operation == "GetRowFilters":

            if (

                    extracted_entity.get("row_filter") is True

                    and resource_type == "table"

            ):

                example["action"]["resource"] = {

                    "table": {

                        "catalogName": values["catalogName"],

                        "schemaName": values["schemaName"],

                        "tableName": values["tableName"]

                    }

                }


            else:

                continue


        elif operation in {
            "InsertIntoTable",
            "UpdateTableColumns",
            "DeleteFromTable"
        }:

            example["action"]["resource"] = {
                "table": {
                    "catalogName": values["catalogName"],
                    "schemaName": values["schemaName"],
                    "tableName": values["tableName"]
                }
            }


        else:
            raise ValueError(
                f"Unsupported operation {operation}"
            )


        examples.append(example)


    return examples


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
        "trino_action": [],

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

    # DO NOT USE .format()
    # Rego examples contain { } which are interpreted as format placeholders.
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

def cosine_similarity(a, b):
    return np.dot(a, b) / (
        np.linalg.norm(a) * np.linalg.norm(b)
    )


def find_best_rego_examples(
    extracted_entity,
    example_rego,
    is_local,
    n=3,
    embedding_url=None,
    client=None,
    embedding_model=None
):

    requested_operations = set(
        extracted_entity["trino_action"]
    )


    # --------------------------------------------------
    # 1. Filter examples by compatible operations
    # --------------------------------------------------

    compatible_examples = []

    for ex in example_rego:

        example_operations = set(
            ex["input"]["extraction"]["trino_action"]
        )

        # keep examples sharing at least one operation
        if requested_operations.intersection(example_operations):

            example_extraction = ex["input"]["extraction"]

            if (
                    extracted_entity.get("column_mask") ==
                    example_extraction.get("column_mask", False)
                    and
                    extracted_entity.get("row_filter") ==
                    example_extraction.get("row_filter", False)
            ):
                compatible_examples.append(ex)


    # fallback
    if not compatible_examples:
        compatible_examples = example_rego



    # --------------------------------------------------
    # 2. Embedding ranking inside compatible examples
    # --------------------------------------------------

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


    ranked = sorted(
        compatible_examples,
        key=lambda ex: cosine_similarity(
            query_embedding,
            ex["embedding"],
        ),
        reverse=True,
    )


    return ranked[:n]


def llm_generate_rego(extracted_entity,example_rego,input_structure,is_local,chat_url=None,client=None,model=None,):
    prompt = [
        {
            "role": "system",
            "content": get_generate_rego_system_prompt(
                example_rego=example_rego,
                input_structure=input_structure,
                extracted_entity=extracted_entity,
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                extracted_entity,
                indent=2,
            ),
        },
    ]

    prompt= json.dumps(prompt,indent=2)

    print("=" * 80)
    print(prompt)
    print("=" * 80)

    response=llm_call(prompt, is_local=is_local,chat_url=chat_url, model=model, client=client)

    return response.strip()


def clean_rego_output(raw):
    """Strip an accidental markdown code fence if the model adds one."""

    raw = raw.strip()

    if raw.startswith("```"):
        lines = raw.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        raw = "\n".join(lines).strip()

    return raw


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
        examples = find_best_rego_examples(
            extracted_entity=extracted_entity,
            example_rego=example_rego,
            is_local=is_local,
            n=3,
            embedding_url=embedding_url,
            client=client,
            embedding_model=embedding_model
        )

        example_text = "\n\n".join(
            ex["output"] for ex in examples
        )

        raw = llm_generate_rego(
            extracted_entity,
            example_text,
            input_structure=input_structure,
            is_local=is_local,
            chat_url=chat_url,
            client=client,
            model=model
        )

        if not raw:
            return ""

        return clean_rego_output(raw)

    except Exception as e:
        print(
            "Failed generate_rego_policy:",
            repr(e)
        )
        return ""
# ---------------------------------------------------------------------------
# Boilerplate that is shared by every role and only needs to exist once in
# the final policy file. Pulled verbatim from the reference policy's
# non-role-specific parts.
# ---------------------------------------------------------------------------
BOILERPLATE_HEADER = '''package trino.authz

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false


user_info := resp.body if {
    user := input.context.identity.user

    resp := http.send({
        "method": "GET",
        "url": sprintf("http://ldap-micro-service:5000/users/%s", [user]),
        "raise_error": false
    })

    print("HTTP RESPONSE:", resp)

    resp.status_code == 200
}

############ ROLES ############

is_admin if {
    input.context.identity.user == "trino"
}

is_test if {
    input.context.identity.user == "test_access"
}

############ ALLOW ############

allow if is_admin
allow if is_test'''

BOILERPLATE_FOOTER = '''##################### BATCH #######################
# this assumes the non-batch response field is called "allow"
batch contains i if {
    some i
    raw_resource := input.action.filterResources[i]
    allow with input.action.resource as raw_resource
}

# Corner case: filtering columns is done with a single table item, and many columns inside
# We cannot use our normal logic in other parts of the policy as they are based on sets
# and we need to retain order
batch contains i if {
    some i
    input.action.operation == "FilterColumns"
    count(input.action.filterResources) == 1
    raw_resource := input.action.filterResources[0]
    count(raw_resource["table"]["columns"]) > 0
    new_resources := [
        object.union(raw_resource, {"table": {"column": column_name}})
        | column_name := raw_resource["table"]["columns"][_]
    ]
    allow with input.action.resource as new_resources[i]
}'''


def _split_into_blocks(rego_text):
    """Split a rego snippet into top-level rule blocks on blank lines."""

    blocks = []
    current = []

    for line in rego_text.splitlines():
        if line.strip() == "":
            if current:
                blocks.append("\n".join(current).strip())
                current = []
        else:
            current.append(line)

    if current:
        blocks.append("\n".join(current).strip())

    return blocks


def _block_signature(block):
    """First non-comment line of a block, used as a dedup key."""

    for line in block.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped

    return block


def assemble_full_policy(role_snippets):
    """
    Merge per-role Rego snippets (each produced by `generate_rego_policy`)
    into one complete, loadable policy file, deduplicating any helper rule
    (e.g. `is_analyst if { ... }`) that shows up more than once because the
    same subject appeared in more than one extracted rule.

    Dedup is a best-effort textual match on each block's first line, so it
    only catches exact repeats -- it will NOT merge two different allow
    scopes for the same role into one rule (nor does it need to: Rego
    `allow if` rules are OR'd together regardless of how many there are).
    """

    seen_signatures = set()
    deduped_blocks = []

    for snippet in role_snippets:
        for block in _split_into_blocks(snippet):
            sig = _block_signature(block)
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)
            deduped_blocks.append(block)

    body = "\n\n".join(deduped_blocks)

    return f"{BOILERPLATE_HEADER}\n\n{body}\n\n{BOILERPLATE_FOOTER}\n"

