import json
import numpy as np

from LLM.Interface.embedding_call import embedding_call
from LLM.Interface.llm_call import llm_call


EXTRACT_SYSTEM_PROMPT_TEMPLATE = """
You are an authorization policy parser.

The user will describe an access rule in natural language.

Interpret the sentence as an authorization policy.

Your task:
1. Identify the subject (user or group).
2. Identify the resource scope.
3. Identify the requested user action.
4. Convert the requested user action into the required Trino authorization actions using the provided action mapping.
5. Detect whether the policy explicitly contains column masking.
6. Detect whether the policy explicitly contains row filtering.
7. Return only the required Trino actions to be granted.

Return ONLY valid JSON. Never explain anything. Never output markdown.

IMPORTANT RULES:

- "trino_action" MUST contain only the authorization actions required by the policy.
- Do not return SQL actions such as SELECT, INSERT, UPDATE.
- Convert SQL operations using the action mapping.
- If the requested operation requires multiple Trino permissions, return all required permissions.
- If the user has unrestricted access, return "*".

COLUMN MASK RULES:

- Set "column_mask": true ONLY if the policy explicitly says:
  - a column is hidden
  - a column is masked
  - a column value must be replaced/redacted
  - a masking expression is provided

- Normal SELECT permission MUST NOT create column masking.

ROW FILTER RULES:

- Set "row_filter": true ONLY if the policy explicitly says:
  - only specific rows are visible
  - rows must be filtered
  - a predicate/condition limits returned rows

- Normal SELECT permission MUST NOT create row filtering.

- If no explicit masking/filtering exists:
    "column_mask": false
    "row_filter": false

- Never add GetColumnMask or GetRowFilters only because Trino SELECT normally supports them.
- Add GetColumnMask only when "column_mask" is true.
- Add GetRowFilters only when "row_filter" is true.


User action to Trino authorization mapping:

{valid_actions}


Output format:

{{
  "subject_attribute": "user" | "groups",
  "subject_value": "",
  "resource_type": "catalog" | "schema" | "table" | "column",
  "resource_values": {{
      "catalogName": "",
      "schemaName": "",
      "tableName": "",
      "columnName": ""
  }},
  "trino_action": [],
  "column_mask": false,
  "row_filter": false
}}


If column_mask is true, optionally include:

"column_mask_policy": {{
    "expression": ""
}}

If row_filter is true, optionally include:

"row_filter_policy": {{
    "expression": ""
}}


Relevant examples:

{examples}

"""


def retrieve_examples(
    rule,
    extraction_indexes,
    is_local,
    n=3,
    embedding_url=None,
    client=None,
    embedding_model=None
):

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

    example_embeddings = (
        example_embeddings /
        np.linalg.norm(
            example_embeddings,
            axis=1,
            keepdims=True
        )
    )

    rule_embedding = (
        rule_embedding /
        np.linalg.norm(rule_embedding)
    )

    scores = example_embeddings @ rule_embedding

    best_indexes = np.argsort(scores)[::-1][:n]

    return [
        extraction_indexes[i]
        for i in best_indexes
    ]


def format_examples(examples):

    result = []

    for ex in examples:

        result.append(
            f"""
Input:
{ex['input']['extraction']}

Output:
{json.dumps(ex['output'], indent=2)}
"""
        )

    return "\n".join(result)



def get_extract_system_prompt(
    check_for_action,
    examples
):

    return EXTRACT_SYSTEM_PROMPT_TEMPLATE.format(

        valid_actions=json.dumps(
            check_for_action,
            indent=2
        ),

        examples=examples
    )



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

        return


    prompt = [
        {
            "role": "system",
            "content": get_extract_system_prompt(
                check_for_action,
                format_examples(examples)
            )
        },
        {
            "role": "user",
            "content": rule
        }
    ]


    prompt = json.dumps(
        prompt,
        indent=2
    )


    try:

        response = llm_call(
            prompt,
            response_format={
                "type": "json_object"
            },
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

        return


    return response.strip()



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

        return


    print(
        "\n[RAW MODEL OUTPUT]\n",
        raw
    )


    result = json.loads(raw)


    # backward safety normalization
    if "column_mask" not in result:
        result["column_mask"] = False

    if "row_filter" not in result:
        result["row_filter"] = False


    # remove unsupported Trino operations
    if not result["column_mask"]:
        result["trino_action"] = [
            x for x in result["trino_action"]
            if x != "GetColumnMask"
        ]

    if not result["row_filter"]:
        result["trino_action"] = [
            x for x in result["trino_action"]
            if x != "GetRowFilters"
        ]


    return result