def gen_index_extraction(client, examples, embedding_model):
    index = []

    for example in examples:
        embedding = client.embeddings.create(
            model=embedding_model,
            input=example["input"]
        ).data[0].embedding

        index.append({
            "input": example["input"],
            "output": example["output"],
            "embedding": embedding
        })

    return index