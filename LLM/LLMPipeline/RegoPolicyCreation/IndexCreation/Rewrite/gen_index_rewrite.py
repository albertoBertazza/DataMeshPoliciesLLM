from Interface.embedding_call import embedding_call   # adjust import path


def gen_index_rewrite(
    examples,
    is_local=False,
    embedding_url=None,
    client=None,
    embedding_model=None
):
    index = []

    for example in examples:

        embedding = embedding_call(
            text=example["rule"],
            is_local=is_local,
            embedding_url=embedding_url,
            client=client,
            embedding_model=embedding_model
        )

        index.append({
            "rule": example["rule"],
            "explanation": example["explanation"],
            "embedding": embedding.tolist()
        })

    return index