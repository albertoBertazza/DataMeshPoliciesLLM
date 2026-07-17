import json
import numpy as np

from LLM.Interface.embedding_call import embedding_call
from LLM.Interface.llm_call import llm_call


TEST_CREATION_SYSTEM_PROMPT_TEMPLATE = """
You are an expert in Trino authorization policy testing.

You receive:
1. A generated authorization rule explanation.
2. A Data Mesh structure containing catalogs, schemas, tables and columns.
3. A list of available Trino users with username, password and groups.

Your task is to generate SQL interaction tests to verify ONLY the authorization rule.

IMPORTANT:

- The rule explanation is the ONLY source of truth for permissions.
- Use the Data Mesh structure ONLY to build valid SQL queries.
- Do NOT invent catalogs, schemas, tables or columns.
- Do NOT infer permissions from user role names.
- A user is allowed ONLY if the rule explicitly grants access.
- Generate tests only for users needed to validate the rule.

Return ONLY valid JSON.
Do not output markdown.

Output format:

{{
  "input": {{
    "rule_explanation": "",
    "data_mesh": {{}},
    "user_credentials": []
  }},
  "output": [
    {{
      "query": "",
      "username": "",
      "password": "",
      "allowed": true
    }}
  ]
}}

Relevant examples:

{examples}
"""


def normalize_examples(indexes):

    if indexes is None:
        return []

    # index returned as dictionary
    if isinstance(indexes, dict):

        if "examples" in indexes:
            indexes = indexes["examples"]

        else:
            indexes = list(indexes.values())


    # nested list
    while (
        isinstance(indexes, list)
        and len(indexes) > 0
        and isinstance(indexes[0], list)
    ):
        indexes = indexes[0]


    return indexes



def retrieve_examples(
    rule,
    data_mesh,
    user_credentials,
    test_creation_example_indexes,
    is_local,
    n=3,
    embedding_url=None,
    client=None,
    embedding_model=None,
):

    examples = normalize_examples(
        test_creation_example_indexes
    )


    embedding_text = json.dumps(
        {
            "rule_explanation": rule,
            "data_mesh": data_mesh,
            "user_credentials": user_credentials
        },
        indent=2
    )


    query_embedding = embedding_call(
        text=embedding_text,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model,
    )


    ranked = []


    for example in examples:

        if not isinstance(example, dict):
            continue


        if "embedding" not in example:
            continue


        example_embedding = np.array(
            example["embedding"]
        )


        score = np.dot(
            query_embedding,
            example_embedding
        ) / (
            np.linalg.norm(query_embedding)
            *
            np.linalg.norm(example_embedding)
        )


        ranked.append(
            (
                score,
                example
            )
        )


    ranked.sort(
        key=lambda x: x[0],
        reverse=True
    )


    return [
        item[1]
        for item in ranked[:n]
    ]



def format_examples(examples):

    formatted = []

    for ex in examples:

        if not isinstance(ex, dict):
            continue


        formatted.append(
            f"""
Input:
{json.dumps(ex.get("input", {}), indent=2)}

Output:
{json.dumps(ex.get("output", {}), indent=2)}
"""
        )


    return "\n".join(formatted)



def get_test_creation_prompt(examples):

    return TEST_CREATION_SYSTEM_PROMPT_TEMPLATE.format(
        examples=examples
    )



def llm_create_tests(
    rule_explanation,
    data_mesh,
    user_credentials,
    test_creation_example_indexes,
    is_local,
    chat_url=None,
    embedding_url=None,
    client=None,
    model=None,
    embedding_model=None,
):


    examples = retrieve_examples(
        rule_explanation,
        data_mesh,
        user_credentials,
        test_creation_example_indexes,
        is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model,
    )


    prompt = [

        {
            "role": "system",
            "content": get_test_creation_prompt(
                format_examples(examples)
            )
        },

        {
            "role": "user",
            "content": json.dumps(
                {
                    "rule_explanation": rule_explanation,
                    "data_mesh": data_mesh,
                    "user_credentials": user_credentials
                },
                indent=2
            )
        }

    ]


    response = llm_call(
        json.dumps(
            prompt,
            indent=2
        ),
        response_format={
            "type": "json_object"
        },
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )


    return response.strip()



def create_trino_tests(
    rule_explanation,
    data_mesh,
    user_credentials,
    test_creation_example_indexes,
    is_local,
    chat_url=None,
    embedding_url=None,
    client=None,
    model=None,
    embedding_model=None,
):


    raw = llm_create_tests(
        rule_explanation=rule_explanation,
        data_mesh=data_mesh,
        user_credentials=user_credentials,
        test_creation_example_indexes=test_creation_example_indexes,
        is_local=is_local,
        chat_url=chat_url,
        embedding_url=embedding_url,
        client=client,
        model=model,
        embedding_model=embedding_model,
    )


    print("\n[RAW MODEL OUTPUT]")
    print(raw)


    return json.loads(raw)