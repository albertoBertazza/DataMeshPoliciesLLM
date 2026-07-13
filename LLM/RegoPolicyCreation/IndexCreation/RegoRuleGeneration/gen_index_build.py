import json
from RegoPolicyCreation.Interface.embedding_call import embedding_call   # adjust import path


def gen_index_build(
    examples,
    is_local=False,
    embedding_url=None,
    client=None,
    embedding_model=None
):
    index = []

    for example in examples:
        # Convert dict → string
        input_text = json.dumps(
            example["input"],
            ensure_ascii=False
        )

        embedding = embedding_call(
            text=input_text,
            is_local=is_local,
            embedding_url=embedding_url,
            client=client,
            embedding_model=embedding_model
        )

        index.append({
            "input": example["input"],
            "output": example["output"],
            "embedding": embedding.tolist()
        })

    return index