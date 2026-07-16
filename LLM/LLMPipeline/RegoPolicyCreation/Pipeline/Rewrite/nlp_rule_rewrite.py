import json
import numpy as np

from LLM.Interface.embedding_call import embedding_call
from LLM.Interface.llm_call import llm_call


def cosine_similarity(a, b):
    return np.dot(a, b) / (
        np.linalg.norm(a) * np.linalg.norm(b)
    )


def find_best_examples(
    rule,
    index,
    is_local,
    n=3,
    embedding_url=None,
    client=None,
    embedding_model=None,
):
    query_embedding = embedding_call(
        text=rule,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model,
    )

    ranked = sorted(
        index,
        key=lambda example: cosine_similarity(
            query_embedding,
            example["embedding"],
        ),
        reverse=True,
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

    messages = [
        {
            "role": "system",
            "content": (
                "You are an expert in Trino access policies.\n\n"

                "Your task is to explain the Trino access rule.\n\n"

                "IMPORTANT:\n"
                "- The Data Mesh Structure provided below is the ONLY source of truth.\n"
                "- Never invent catalogs, schemas, tables or columns.\n"
                "- Never copy catalog, schema, table or column names from the examples.\n"
                "- The retrieved examples illustrate ONLY the explanation style.\n"
                "- If an example contains resources that differ from the Data Mesh Structure, IGNORE them.\n"
                "- Always validate every resource against the provided Data Mesh Structure before generating the explanation.\n\n"

                "Return ONLY a valid JSON object with exactly this structure:\n\n"

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

                "### Existing Security Groups\n"
                f"{json.dumps(security_groups, indent=2)}\n\n"

                "If the rule refers to a security group not listed above:\n"
                "- set existSecureGroup=false\n"
                "- explain that the security group does not exist.\n\n"

                "### Existing Data Mesh Structure\n"
                f"{json.dumps(data_mesh_structure, indent=2)}\n\n"

                "If any catalog, schema, table or column referenced by the rule does not exist in the Data Mesh Structure:\n"
                "- set pathExistOnDataMeshStructure=false\n"
                "- explain exactly which part of the path does not exist.\n"
            ),
        }
    ]

    # Examples are explicitly marked as examples only
    for example in examples:
        messages.append({
            "role": "system",
            "content": (
                "Example for style only. "
                "Do NOT reuse the resource names appearing in this example."
            ),
        })

        messages.append({
            "role": "user",
            "content": example["input"]["rule"],
        })

        messages.append({
            "role": "assistant",
            "content": json.dumps(
                example["explanation"],
                indent=2,
            ),
        })

    messages.append({
        "role": "user",
        "content": (
            "Rule:\n"
            f"{rule}\n\n"
            "Remember:\n"
            "- Ignore all resource names that appeared in the examples.\n"
            "- Use ONLY the Data Mesh Structure provided in the system prompt."
        ),
    })

    prompt = json.dumps(messages, indent=2)

    response = llm_call(
        prompt,
        temperature=0.0,
        response_format={"type": "json_object"},
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