import json
import numpy as np

from LLM.Interface.embedding_call import embedding_call
from LLM.Interface.llm_call import llm_call


TEST_CREATION_SYSTEM_PROMPT_TEMPLATE = """
You are an expert in Trino authorization policy testing.

You receive:
1. A generated authorization rule explanation.
2. A list of available Trino users with username, password and groups.

Your task is to generate SQL interaction tests to verify ONLY the authorization rule.

IMPORTANT:

- The rule explanation is the ONLY source of truth.
- Do NOT infer permissions from user role names.
- Do NOT assume admin, manager, engineer or any other group has access unless explicitly stated in the rule.
- A user is allowed ONLY if one of its groups or username matches the subject described in the rule.
- If the rule says a group can access a resource, only users belonging to that group can have allowed=true.
- All other users must have allowed=false.
- Generate tests only for the users needed to validate the rule.
- Do not generate tests for unrelated users.

For each test:
- query: a valid Trino SQL statement matching the resource and action from the rule.
- username: must come from the provided user_credentials.
- password: must come from the provided user_credentials.
- allowed:
    true  -> only if the user should have permission according to the rule.
    false -> if the user should be denied by the rule.

Return ONLY valid JSON.
Do not explain anything.
Do not output markdown.


Output format:

{{
  "input": {{
    "rule_explanation": "",
    "user_credentials": [
      {{
        "username": "",
        "password": "",
        "groups": []
      }}
    ]
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


Example:

Rule:
"The Analyst role is a read-only role. It should be allowed to execute SELECT statements on catalog: iceberg, schema: demographics, table: employees."

Correct output:

{{
  "output": [
    {{
      "query": "SELECT * FROM iceberg.demographics.employees;",
      "username": "analyst",
      "password": "analyst123",
      "allowed": true
    }},
    {{
      "query": "INSERT INTO iceberg.demographics.employees VALUES (...);",
      "username": "analyst",
      "password": "analyst123",
      "allowed": false
    }}
  ]
}}

Wrong output:
- Do not test admin users.
- Do not give access to hr_manager, finance_manager, data_engineer unless the rule explicitly grants them access.
- Do not create tests for every available user.

Relevant examples:

{examples}
"""


def retrieve_examples(
    rule,
    user_credentials,
    test_creation_example_indexes,
    is_local,
    n=3,
    embedding_url=None,
    client=None,
    embedding_model=None,
):

    # Include credentials in embedding context
    embedding_text = json.dumps(
        {
            "rule_explanation": rule,
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

    ranked = sorted(
        test_creation_example_indexes,
        key=lambda example: np.dot(
            query_embedding,
            example["embedding"],
        )
        / (
            np.linalg.norm(query_embedding)
            * np.linalg.norm(example["embedding"])
        ),
        reverse=True,
    )

    return ranked[:n]


def format_examples(examples):

    formatted = []

    for ex in examples:

        formatted.append(
            f"""
Input:
{json.dumps(ex["input"], indent=2)}

Output:
{json.dumps(ex["output"], indent=2)}
"""
        )

    return "\n".join(formatted)


def get_test_creation_prompt(examples):

    return TEST_CREATION_SYSTEM_PROMPT_TEMPLATE.format(
        examples=examples
    )


def llm_create_tests(
    rule_explanation,
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
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "rule_explanation": rule_explanation,
                    "user_credentials": user_credentials
                },
                indent=2
            ),
        },
    ]

    prompt = json.dumps(prompt, indent=2)

    response = llm_call(
        prompt,
        response_format={"type": "json_object"},
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    return response.strip()


def create_trino_tests(
    rule_explanation,
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
        user_credentials=user_credentials,
        test_creation_example_indexes=test_creation_example_indexes,
        is_local=is_local,
        chat_url=chat_url,
        embedding_url=embedding_url,
        client=client,
        model=model,
        embedding_model=embedding_model,
    )

    print("\n[RAW MODEL OUTPUT]\n")
    print(raw)

    return json.loads(raw)