import requests
import numpy as np


def embedding_call(text, is_local=False, url=None, client=None,embedding_model=None):
    """
    Returns a numpy embedding vector.

    Parameters
    ----------
    text : str

    is_local : bool
        True  -> local embedding server
        False -> OpenAI-compatible API

    url : str
        Local embedding endpoint.

    client :
        OpenAI client.

    embedding_model : str
        Embedding model name.
    """

    # LOCAL
    if is_local:

        if url is None:
            raise ValueError("url is required when is_local=True")

        response = requests.post(
            url,
            json={
                "input": text,
            },
        )

        response.raise_for_status()

        data = response.json()

        # adapt this depending on your server output
        return np.array(data["embedding"], dtype=np.float32)

    # REMOTE
    if client is None or embedding_model is None:
        raise ValueError(
            "client and model are required when is_local=False"
        )

    response = client.embeddings.create(
        model=embedding_model,
        input=text,
    )

    return np.array(
        response.data[0].embedding,
        dtype=np.float32,
    )