import json
import os
import time

from Function.jsonHelper import load_json


def get_index_path(directory, filename, embedding_model):

    model_name = sanitize_model_name(embedding_model)

    return os.path.join(
        directory,
        f"{filename}_{model_name}.json"
    )


def sanitize_model_name(model):
    return (
        model
        .replace(":", "_")
        .replace("/", "_")
        .replace("\\", "_")
        .replace(".", "_")
        .replace("-", "_")
    )



def save_index(
    output_path,
    source_path,
    examples,
    embedding_model=None,
    embedding_url=None,
    is_local=False
):
    embedding_identifier = embedding_url if is_local else embedding_model

    payload = {
        "source_file": str(source_path),
        "source_mtime": os.path.getmtime(source_path),
        "created_at": time.time(),
        "embedding_model": embedding_identifier,
        "examples": examples
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def load_index(path):

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def needs_rebuild(
    source_path,
    index_path,
    embedding_model
):
    # index missing
    if not os.path.exists(index_path):
        return True

    try:
        index = load_index(index_path)
    except Exception:
        return True

    # source changed
    source_mtime = os.path.getmtime(source_path)

    saved_mtime = index.get(
        "source_mtime",
        0
    )

    if source_mtime > saved_mtime:
        return True

    # embedding model changed
    saved_embedding_model = index.get(
        "embedding_model",
        None
    )

    if saved_embedding_model != embedding_model:
        return True

    return False

def build_index_if_needed(
    input_path,
    output_path,
    generator,
    is_local=False,
    embedding_url=None,
    client=None,
    embedding_model=None,
):

    if not needs_rebuild(
        input_path,
        output_path,
        embedding_model
    ):
        print(f"Index already up to date: {output_path}")
        return load_index(output_path)["examples"]

    print(f"Rebuilding index: {output_path}")

    examples = load_json(input_path)

    index = generator(
        examples=examples,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model
    )

    save_index(
        output_path,
        input_path,
        index,
        embedding_model=embedding_model
    )

    print(f"Created {len(index)} embeddings.")

    return index

def reload_indexes(
    is_local=False,
    embedding_url=None,
    client=None,
    embedding_model=None,
    database_path=None,
    index_path=None,
    filename= '',
    gen_index_function=None,

):

    index_suffix = embedding_url if is_local else embedding_model

    index_path_final = get_index_path(
        index_path,
        filename,
        index_suffix
    )

    loaded_index = build_index_if_needed(
        database_path,
        index_path_final,
        gen_index_function,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model,
    )

    return  loaded_index



