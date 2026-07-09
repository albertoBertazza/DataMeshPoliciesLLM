from openai import OpenAI
from dotenv import load_dotenv
import json
import os
import time

from RemoteLLM.IndexCreation.Extraction.gen_index_extraction import gen_index_extraction
from RemoteLLM.IndexCreation.RegoRuleGeneration.gen_index_build import gen_index_build
from RemoteLLM.IndexCreation.Rewrite.gen_index_rewrite import gen_index_rewrite

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

load_dotenv()

LLM_DIR = os.getenv("LLM_DIR")

# join with path /Example/Datastore
EXAMPLE_DIR = os.path.join(LLM_DIR, "Example")

INPUT_DIR = os.path.join( EXAMPLE_DIR, "Datastore")
OUTPUT_DIR = os.path.join(EXAMPLE_DIR, "Indexed")

INPUT_EXTRACTION_PATH = os.path.join( os.path.join(INPUT_DIR, "Extraction"), "extraction.json")
INPUT_REWRITE_RULE_PATH = os.path.join( os.path.join(INPUT_DIR, "Rewrite"), "rewrite_rule.json")
INPUT_BUILD_REGO_PATH = os.path.join( os.path.join(INPUT_DIR, "RegoRuleGeneration"), "build_rego.json")

OUTPUT_EXTRACTION_INDEX_PATH = os.path.join( os.path.join(OUTPUT_DIR, "Extraction"), "extraction_index.json")
OUTPUT_REWRITE_RULE_INDEX_PATH = os.path.join( os.path.join(OUTPUT_DIR, "Rewrite"), "rewrite_rule_index.json")
OUTPUT_BUILD_REGO_INDEX_PATH = os.path.join( os.path.join(OUTPUT_DIR, "RegoRuleGeneration"), "build_rego_index.json")


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)




def save_index(
    output_path,
    source_path,
    examples,
    embedding_model="text-embedding-3-small"
):
    payload = {
        "source_file": source_path,
        "source_mtime": os.path.getmtime(source_path),
        "created_at": time.time(),
        "embedding_model": embedding_model,
        "examples": examples
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def load_index(path):

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def needs_rebuild(
    source_path,
    index_path
):
    # index missing
    if not os.path.exists(index_path):
        return True

    try:
        index = load_index(index_path)
    except Exception:
        return True

    source_mtime = os.path.getmtime(source_path)

    saved_mtime = index.get(
        "source_mtime",
        0
    )

    return source_mtime > saved_mtime

def build_index_if_needed(client, input_path, output_path, generator):
    if not needs_rebuild(input_path,output_path):
        print( f"Index already up to date: {output_path}" )

        return load_index(output_path)["examples"]

    print(
        f"Rebuilding index: {output_path}"
    )

    examples = load_json(
        input_path
    )

    index = generator(
        client,
        examples
    )

    save_index(
        output_path,
        input_path,
        index
    )

    print(
        f"Created {len(index)} embeddings."
    )

    return index


def reload_indexes(client):
    extraction_index = build_index_if_needed(
        client,
        INPUT_EXTRACTION_PATH,
        OUTPUT_EXTRACTION_INDEX_PATH,
        gen_index_extraction
    )

    rewrite_rule_index = build_index_if_needed(
        client,
        INPUT_REWRITE_RULE_PATH,
        OUTPUT_REWRITE_RULE_INDEX_PATH,
        gen_index_rewrite
    )

    build_rego_index = build_index_if_needed(
        client,
        INPUT_BUILD_REGO_PATH,
        OUTPUT_BUILD_REGO_INDEX_PATH,
        gen_index_build
    )

    return extraction_index, rewrite_rule_index, build_rego_index



