import json
from functools import lru_cache
import numpy as np


EXTRACT_SYSTEM_PROMPT_TEMPLATE = """
You are an authorization policy parser.

The user will describe an access rule in natural language.

Interpret the sentence as an authorization policy.

Your task:
1. Identify the subject (user or group).
2. Identify the resource scope.
3. Identify the requested user action.
4. Convert the requested user action into the required Trino authorization actions using the provided action mapping.
5. Return only the required Trino actions to be granted.

Return ONLY valid JSON. Never explain anything. Never output markdown.

IMPORTANT RULES:

- If the subject is a group, "subject_value" MUST be one of the allowed security groups.
- Never invent group names.
- If a group is mentioned but it does not exist in security_groups, do not extract it as a valid group.
- Prefer exact group names when matching.
- Users are free text identifiers.
- Groups are controlled vocabulary.
- "trino_action" MUST contain the authorization actions required by the requested operation.
- Do not return SQL actions such as SELECT, INSERT, UPDATE. Convert them using the action mapping.
- If the requested operation requires multiple Trino permissions, return all required permissions.
- If the user has unrestricted access, return "*".


Available security groups:

{security_groups}


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
  "trino_action": []
}}


Relevant examples:

{examples}

"""


def get_embedding(client, text):

    response = client.embeddings.create(
        model="text-embedding-3-small",
        input=text
    )

    return np.array(
        response.data[0].embedding
    )


def retrieve_examples(client, rule, extraction_indexes, n=3):

    texts = [
        x["input"]
        for x in extraction_indexes
    ]

    example_embeddings = np.array(
        [
            get_embedding(client, t)
            for t in texts
        ]
    )

    rule_embedding = get_embedding(
        client,
        rule
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
{ex['input']}

Output:
{json.dumps(ex['output'], indent=2)}
"""
        )

    return "\n".join(result)



def get_extract_system_prompt(
    check_for_action,
    security_groups,
    examples
):

    return EXTRACT_SYSTEM_PROMPT_TEMPLATE.format(

        valid_actions=json.dumps(
            check_for_action,
            indent=2
        ),

        security_groups=json.dumps(
            security_groups,
            indent=2
        ),

        examples=examples
    )



def llm_extract(
    client,
    model,
    rule,
    check_for_action,
    extraction_index,
    security_groups
):

    examples = retrieve_examples(
        client,
        rule,
        extraction_index,
        n=3
    )


    response = client.chat.completions.create(

        model=model,

        temperature=0,

        response_format={
            "type": "json_object"
        },

        messages=[

            {
                "role": "system",
                "content":
                    get_extract_system_prompt(
                        check_for_action,

                        [
                            g["name"]
                            for g in security_groups
                        ],

                        format_examples(
                            examples
                        )
                    )
            },

            {
                "role": "user",
                "content": rule
            }

        ]
    )


    return response.choices[0].message.content



def extract_entities(
    client,
    model,
    rule,
    check_for_action,
    extraction_indexes,
    security_groups
):

    raw = llm_extract(
        client,
        model,
        rule,
        check_for_action,
        extraction_indexes,
        security_groups
    )


    print(
        "\n[RAW MODEL OUTPUT]\n",
        raw
    )


    raw = raw.strip()


    start = raw.find("{")
    end = raw.rfind("}")


    if start == -1 or end == -1:
        raise ValueError(
            "No JSON found in model output"
        )


    result = json.loads(
        raw[start:end+1]
    )


    if result["subject_attribute"] == "groups":

        allowed_groups = {
            g["name"]
            for g in security_groups
        }


        if result["subject_value"] not in allowed_groups:

            raise ValueError(
                f"Invalid security group extracted: "
                f"{result['subject_value']}"
            )


    return result