from dotenv import load_dotenv
import json
import os
import time

from LLM.LLMPipeline.RegoPolicyCreation.IndexCreation.Extraction.gen_index_extraction import gen_index_extraction
from LLM.LLMPipeline.RegoPolicyCreation.IndexCreation.RegoRuleGeneration.gen_index_build import gen_index_build
from LLM.LLMPipeline.RegoPolicyCreation.IndexCreation.Rewrite.gen_index_rewrite import gen_index_rewrite

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

load_dotenv()
DATA_MESH_DIR = os.getcwd()

LLM_DIR= os.path.join(DATA_MESH_DIR, "LLM")

print(LLM_DIR)

LLM_PIPELINE_DIR = os.path.join(LLM_DIR, "LLMPipeline")
REGO_POLICY_CREATION_DIR = os.path.join(LLM_PIPELINE_DIR, "RegoPolicyCreation")

# join with path /Example/Datastore
EXAMPLE_DIR = os.path.join(REGO_POLICY_CREATION_DIR, "Example")

INPUT_DIR = os.path.join( EXAMPLE_DIR, "Datastore")
OUTPUT_DIR = os.path.join(EXAMPLE_DIR, "Indexed")

INPUT_EXTRACTION_PATH = os.path.join( os.path.join(INPUT_DIR, "Extraction"), "extraction.json")
INPUT_REWRITE_RULE_PATH = os.path.join( os.path.join(INPUT_DIR, "Rewrite"), "rewrite_rule.json")
INPUT_BUILD_REGO_PATH = os.path.join( os.path.join(INPUT_DIR, "RegoRuleGeneration"), "build_rego.json")


def get_index_path(directory, filename, embedding_model):

    model_name = sanitize_model_name(embedding_model)

    return os.path.join(
        directory,
        f"{filename}_{model_name}.json"
    )




def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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
        "source_file": source_path,
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
    embedding_model=None
):

    index_suffix = embedding_url if is_local else embedding_model

    extraction_index_path = get_index_path(
        os.path.join(OUTPUT_DIR, "Extraction"),
        "extraction_index",
        index_suffix
    )

    rewrite_index_path = get_index_path(
        os.path.join(OUTPUT_DIR, "Rewrite"),
        "rewrite_rule_index",
        index_suffix
    )

    build_rego_index_path = get_index_path(
        os.path.join(OUTPUT_DIR, "RegoRuleGeneration"),
        "build_rego_index",
        index_suffix
    )

    # extraction_index = build_index_if_needed(
    #     INPUT_EXTRACTION_PATH,
    #     extraction_index_path,
    #     gen_index_extraction,
    #     is_local=is_local,
    #     embedding_url=embedding_url,
    #     client=client,
    #     embedding_model=embedding_model,
    # )

    rewrite_rule_index = build_index_if_needed(
        INPUT_REWRITE_RULE_PATH,
        rewrite_index_path,
        gen_index_rewrite,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model,
    )

    build_rego_index = build_index_if_needed(
        INPUT_BUILD_REGO_PATH,
        build_rego_index_path,
        gen_index_build,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model,
    )

    return rewrite_rule_index, build_rego_index



