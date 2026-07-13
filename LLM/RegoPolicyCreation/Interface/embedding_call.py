import requests
import numpy as np


def embedding_call(text, is_local=False, embedding_url=None, client=None, embedding_model=None):

    # LOCAL
    if is_local:

        if embedding_url is None:
            raise ValueError("embedding_url is required when is_local=True")

        embedding_url=embedding_url+"/v1/embeddings"
        response = requests.post(
            embedding_url,
            json={
                "input": text,
            },
        )

        response.raise_for_status()

        data = response.json()

        return np.array(
            data["data"][0]["embedding"],
            dtype=np.float32,
        )

    # REMOTE
    if client is None or embedding_model is None:
        raise ValueError(
            "client and embedding_model are required when is_local=False"
        )

    response = client.embeddings.create(
        model=embedding_model,
        input=text,
    )

    return np.array(
        response.data[0].embedding,
        dtype=np.float32,
    )