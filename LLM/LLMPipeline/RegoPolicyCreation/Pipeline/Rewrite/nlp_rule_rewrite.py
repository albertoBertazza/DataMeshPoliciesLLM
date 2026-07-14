import numpy as np
import json

from Interface.embedding_call import embedding_call
from Interface.llm_call import llm_call


def cosine_similarity(a, b):
    return np.dot(a, b) / (
        np.linalg.norm(a) * np.linalg.norm(b)
    )





def find_best_examples(rule, index,is_local, n=3, embedding_url=None, client=None, embedding_model=None):
    query_embedding = embedding_call(text=rule, is_local=is_local,embedding_url=embedding_url,client=client,embedding_model=embedding_model)

    ranked = sorted(
        index,
        key=lambda example: cosine_similarity(
            query_embedding,
            example["embedding"]
        ),
        reverse=True
    )

    return ranked[:n]


def llm_explain( rule, example_index,is_local, n=3,chat_url=None, embedding_url=None,client=None,model=None, embedding_model=None):

    examples = find_best_examples(rule,example_index,is_local, n=n, embedding_url=embedding_url, client=client, embedding_model=embedding_model)

    for example in examples:
        print(f"(using example: {example['rule']})")

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

    prompt= json.dumps(messages,indent=2)

    response= llm_call(prompt,temperature=0.2, max_tokens=120,is_local=is_local, chat_url=chat_url,client=client,model=model)

    return response.strip()