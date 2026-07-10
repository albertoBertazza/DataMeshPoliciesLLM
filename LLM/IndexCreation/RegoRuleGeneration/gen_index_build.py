import json

def gen_index_build(client, examples, embedding_model):
    index = []

    for example in examples:
        # Convert dict → string
        input_text = json.dumps(example["input"], ensure_ascii=False)

        embedding = client.embeddings.create(
            model=embedding_model,
            input=input_text
        ).data[0].embedding

        index.append({
            "input": example["input"],
            "output": example["output"],
            "embedding": embedding
        })

    return index
