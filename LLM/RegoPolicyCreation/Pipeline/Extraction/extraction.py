import json
import numpy as np

from RegoPolicyCreation.Interface.embedding_call import embedding_call
from RegoPolicyCreation.Interface.llm_call import llm_call


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


def retrieve_examples(rule, extraction_indexes,is_local, n=3, embedding_url=None,client=None, embedding_model=None ):

    texts = [
        x["input"]
        for x in extraction_indexes
    ]

    example_embeddings = np.array(
        [
            embedding_call(text=text, is_local=is_local,embedding_url=embedding_url,client=client, embedding_model=embedding_model)
            for text in texts
        ]
    )

    rule_embedding = embedding_call(text=rule, is_local=is_local,embedding_url=embedding_url,client=client, embedding_model=embedding_model)

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



def llm_extract(rule, check_for_action,extraction_indexes,security_groups, is_local, chat_url=None, embedding_url=None,client=None,model=None, embedding_model=None):

    try:
        examples = retrieve_examples(rule,extraction_indexes,is_local, n=3, embedding_url=embedding_url,client=client, embedding_model=embedding_model)
    except Exception as e:
        print("  Failed to retrieve_examples in llm_extract:", e)
        return
    prompt=[

            {
                "role": "system",
                "content":
                    get_extract_system_prompt(
                        check_for_action,

                        [
                            g["name"] if isinstance(g, dict) else g
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

    # cast prompt to string
    prompt=json.dumps(prompt,indent=2)

    try:
        response = llm_call(prompt,response_format={"type": "json_object"},is_local=is_local,chat_url=chat_url,client=client,model=model)
    except Exception as e:
        print("  Failed to llm_call in llm_extract:", e)
        return
    return response.strip()



def extract_entities(rule,check_for_action,extraction_indexes,security_groups, is_local, chat_url=None, embedding_url=None,client=None,model=None, embedding_model=None):

    try:
        raw = llm_extract(rule=rule,check_for_action=check_for_action,extraction_indexes=extraction_indexes,security_groups=security_groups, is_local=is_local, chat_url=chat_url ,embedding_url=embedding_url,client=client,model=model, embedding_model=embedding_model)
    except Exception as e:
        print("  Failed to llm_extract in extract_entities:", e)
        return


    print(
        "\n[RAW MODEL OUTPUT]\n",
        raw
    )


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
            g["name"] if isinstance(g, dict) else g
            for g in security_groups

        }


        if result["subject_value"] not in allowed_groups:

            raise ValueError(
                f"Invalid security group extracted: "
                f"{result['subject_value']}"
            )


    return result