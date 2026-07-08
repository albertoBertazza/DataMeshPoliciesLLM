import json
from functools import lru_cache
from sentence_transformers import SentenceTransformer
import numpy as np



EXTRACT_SYSTEM_PROMPT_TEMPLATE = """
You are an authorization policy parser.

The user will describe an access rule in natural language.

Interpret the sentence as an authorization policy.

Return ONLY valid JSON. Never explain anything. Never output markdown.

IMPORTANT RULES:

- If the subject is a group, "subject_value" MUST be one of the allowed security groups.
- Never invent group names.
- If a group is mentioned but it does not exist in security_groups, do not extract it as a valid group.
- Prefer exact group names when matching.
- Users are free text identifiers.
- Groups are controlled vocabulary.

Available security groups:

{security_groups}


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
  "trino_action": "*"
}}


Valid Trino actions:

{valid_actions}


Relevant examples:

{examples}

"""



@lru_cache()
def get_embedding_model():

    return SentenceTransformer(
        "all-MiniLM-L6-v2"
    )


def retrieve_examples(rule, extraction_indexes, n=3):

    model = get_embedding_model()

    texts = [
        x["input"]
        for x in extraction_indexes
    ]

    example_embeddings = model.encode(
        texts,
        normalize_embeddings=True
    )

    rule_embedding = model.encode(
        rule,
        normalize_embeddings=True
    )


    scores = np.dot(
        example_embeddings,
        rule_embedding
    )


    best_indexes = np.argsort(scores)[::-1][:n]


    return [
        security_groups[i]
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



def llm_extract(client,model,rule,check_for_action,extraction_index):

    examples = retrieve_examples(rule, extraction_index,  n=3)

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
                        format_examples(examples)
                    )
            },

            {
                "role": "user",
                "content": rule
            }
        ]
    )

    return response.choices[0].message.content



def extract_entities(client,model,rule,check_for_action,security_groups,extraction_indexes):

    raw = llm_extract(client,model,rule,check_for_action,security_groups,extraction_indexes)

    print("\n[RAW MODEL OUTPUT]\n",raw)


    raw = raw.strip()

    start = raw.find("{")
    end = raw.rfind("}")


    if start == -1 or end == -1:
        raise ValueError(
            "No JSON found in model output"
        )


    json_str = raw[start:end+1]

    result = json.loads(json_str)


    # final deterministic validation
    if result["subject_attribute"] == "groups":

        allowed = {
            g["name"]
            for g in security_groups
        }

        if result["subject_value"] not in allowed:
            raise ValueError(f"Invalid security group extracted: " f"{result['subject_value']}")


    return result