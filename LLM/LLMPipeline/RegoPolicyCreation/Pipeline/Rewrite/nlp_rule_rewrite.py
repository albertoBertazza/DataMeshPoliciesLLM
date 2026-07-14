import numpy as np
import json

from Interface.embedding_call import embedding_call
from Interface.llm_call import llm_call


def cosine_similarity(a, b):
    return np.dot(a, b) / (
        np.linalg.norm(a) * np.linalg.norm(b)
    )


def find_best_examples(rule, index, is_local, n=3,
                       embedding_url=None,
                       client=None,
                       embedding_model=None):

    query_embedding = embedding_call(
        text=rule,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model
    )

    ranked = sorted(
        index,
        key=lambda example: cosine_similarity(
            query_embedding,
            example["embedding"]
        ),
        reverse=True
    )

    return ranked[:n]


def llm_explain(
    rule,
    example_index,
    data_mesh_structure,
    security_groups,
    is_local,
    n=3,
    chat_url=None,
    embedding_url=None,
    client=None,
    model=None,
    embedding_model=None,
):

    examples = find_best_examples(
        rule,
        example_index,
        is_local,
        n=n,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model,
    )

    # for example in examples:
    #     print(f"(using example: {example['input']['rule']})")

    messages = [
        {
            "role": "system",
            "content": (
                "You are an expert in Trino access policies.\n\n"

                "Your task is to explain the Trino access rule.\n\n"

                "Return ONLY a valid JSON object with exactly this structure:\n"
                
                "{\n"
                '  "text": "<explanation>",\n'
                '  "existSecureGroup": true,\n'
                '  "pathExistOnDataMeshStructure": true\n'
                "}\n\n"
                
                "Do not return markdown.\n"
                "Do not wrap the JSON inside ```.\n"
                "Return only the JSON object.\n\n"
                
                "If the resource is catalog.schema.table, rewrite it as:\n"
                "catalog: <catalog>, schema: <schema>, table: <table>.\n\n"

                "### Security Groups\n"
                "Only the following security groups exist.\n"
                "Never invent or rename security groups.\n"
                f"{json.dumps(security_groups, indent=2)}\n\n"

                "If the rule refers to a security group that is not listed above, "
                "explicitly state that the security group does not exist.\n\n"

                "### Data Mesh Structure\n"
                "Only the following catalogs, schemas, tables and columns exist.\n"
                "Never invent catalogs, schemas, tables or columns.\n"
                f"{json.dumps(data_mesh_structure, indent=2)}\n\n"

                "If the rule refers to a catalog, schema, table or column that is "
                "not present in the data mesh structure, explain that the requested "
                "path does not exist instead of describing it."
            ),
        }
    ]

    # Add retrieved few-shot examples
    for example in examples:
        messages.append({
            "role": "user",
            "content": example["input"]["rule"],
        })

        messages.append({
            "role": "assistant",
            "content": example["explanation"]["text"],
        })

    # Add the real rule
    messages.append({
        "role": "user",
        "content": rule,
    })

    prompt = json.dumps(messages, indent=2)

    response = llm_call(
        prompt,
        temperature=0.2,
        max_tokens=120,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    response = response.strip()

    try:
        return json.loads(response)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned invalid JSON:\n{response}") from e