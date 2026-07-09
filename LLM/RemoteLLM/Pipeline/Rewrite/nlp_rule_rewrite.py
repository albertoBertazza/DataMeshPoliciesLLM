import numpy as np

def cosine_similarity(a, b):
    return np.dot(a, b) / (
        np.linalg.norm(a) * np.linalg.norm(b)
    )





def find_best_examples(client, rule, index, n=3, embedding_model="text-embedding-3-small"):
    query_embedding = client.embeddings.create(
        model=embedding_model,
        input=rule
    ).data[0].embedding

    ranked = sorted(
        index,
        key=lambda example: cosine_similarity(
            query_embedding,
            example["embedding"]
        ),
        reverse=True
    )

    return ranked[:n]


def llm_explain(client, model, rule, example_index, n=3):

    examples = find_best_examples(
        client,
        rule,
        example_index,
        n=n
    )

    # for example in examples:
    #     print(f"(using example: {example['rule']})")

    messages = [
        {
            "role": "system",
            "content": (
                "Explain the Trino access rule in one sentence. "
                "If the resource is catalog.schema.table, rewrite it as "
                "catalog: <catalog>, schema: <schema>, table: <table>."
            )
        }
    ]

    # Add retrieved few-shot examples
    for example in examples:
        messages.append({
            "role": "user",
            "content": example["rule"]
        })
        messages.append({
            "role": "assistant",
            "content": example["explanation"]
        })

    # Add the real rule
    messages.append({
        "role": "user",
        "content": rule
    })

    response = client.chat.completions.create(
        model=model,
        temperature=0.2,
        max_tokens=120,
        messages=messages
    )

    return response.choices[0].message.content.strip()