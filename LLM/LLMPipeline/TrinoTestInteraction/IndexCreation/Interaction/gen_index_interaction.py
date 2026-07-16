from LLM.Interface.embedding_call import embedding_call


def gen_index_test_creation(
    examples,
    is_local=False,
    embedding_url=None,
    client=None,
    embedding_model=None,
):
    index = []

    for example in examples:

        embedding = embedding_call(
            text=example["input"]["rule_explanation"],
            is_local=is_local,
            embedding_url=embedding_url,
            client=client,
            embedding_model=embedding_model,
        )

        if hasattr(embedding, "tolist"):
            embedding = embedding.tolist()

        index.append({
            "input": example["input"],
            "output": example["output"],
            "embedding": embedding,
        })

    return index