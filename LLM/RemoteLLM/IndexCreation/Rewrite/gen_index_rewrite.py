def gen_index_rewrite(client, examples, embedding_model="text-embedding-3-small"):
    index = []

    for example in examples:
        embedding = client.embeddings.create(
            model=embedding_model,
            input=example["rule"]
        ).data[0].embedding

        index.append({
            "rule": example["rule"],
            "explanation": example["explanation"],
            "embedding": embedding
        })

    return index