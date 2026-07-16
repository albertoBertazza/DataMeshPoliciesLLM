import json
import os
from dotenv import load_dotenv
from openai import OpenAI

from LLM.Interface.activate_local_llm import activate_llm
from LLM.LLMPipeline.RegoPolicyCreation.IndexCreation.index_creator import reload_indexes
from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.Extraction.extraction import extract_entities
from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.RegoRuleGeneration.build_rego import generate_rego_policy
from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.Rewrite.nlp_rule_rewrite import llm_explain

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# LOCAL LLM
CHAT_URL = "http://127.0.0.1:8080"
EMBEDDING_URL = "http://127.0.0.1:8081"
# REMOTE LLM
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
EMBEDDING_MODEL ="text-embedding-3-small"

# WHICH LLM TO USE
IS_LOCAL = os.getenv("IS_LOCAL", "False") == "True"

DATA_MESH_DIR = os.getcwd()

LLM_DIR= os.path.join(DATA_MESH_DIR, "LLM")


STRUCTURE_DIR = os.path.join(LLM_DIR, "Structure")

CHECK_FOR_ACTION_PATH = os.path.join(STRUCTURE_DIR, "checkForAction.json")
INPUT_SCHEMA_PATH = os.path.join(STRUCTURE_DIR, "input.json")
SECURITY_GROUPS_PATH=os.path.join(STRUCTURE_DIR, "security_groups.json")
DATA_MESH_STRUCTURE_PATH=os.path.join(STRUCTURE_DIR, "data_mesh.json")

LLM_PIPELINE_DIR = os.path.join(LLM_DIR, "LLMPipeline")
REGO_POLICY_CREATION_DIR = os.path.join(LLM_PIPELINE_DIR, "RegoPolicyCreation")

OUTPUT_DIR=os.path.join(REGO_POLICY_CREATION_DIR, "output")
OUTPUT_REGO_DIR=os.path.join(OUTPUT_DIR, "rego_policies")

EXAMPLE_DIR = os.path.join(REGO_POLICY_CREATION_DIR, "ExampleDatastore")

REWRITE_RULE_EXAMPLES_PATH = os.path.join(EXAMPLE_DIR, "rewrite_rule.json")
EXTRACTION_EXAMPLES_PATH = os.path.join(EXAMPLE_DIR, "extraction.json")




def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Loaded once at startup - these are the two files you already have
CHECK_FOR_ACTION = load_json(CHECK_FOR_ACTION_PATH)   # action -> [checks...]
INPUT_SCHEMA = load_json(INPUT_SCHEMA_PATH)           # shape Trino sends to OPA
SECURITY_GROUPS = load_json(SECURITY_GROUPS_PATH)
DATA_MESH = load_json(DATA_MESH_STRUCTURE_PATH)

LLAMA_DIR = r"C:\Users\berta\BertaFiles\Project\DataMeshPoliciesLLM\LLM\LocalLLMIntelIpex\llama-cpp-ipex-llm-2.3.0b20250424-win"

activate_llm(LLAMA_DIR, IS_LOCAL, CHAT_URL,"Qwen2.5.1-Coder-7B-Instruct-Q4_K_M.gguf", '8080' )
activate_llm(LLAMA_DIR, IS_LOCAL, EMBEDDING_URL, "nomic-embed-text-v1.5.f16.gguf",  '8081', other_params=' --embedding')



INDEX_EXTRACTION, INDEX_REWRITE_RULE, INDEX_BUILD_REGO = reload_indexes(IS_LOCAL,embedding_url=EMBEDDING_URL, client=client, embedding_model=EMBEDDING_MODEL)

VALID_ACTIONS = list(CHECK_FOR_ACTION.keys())




def process_rule(rule):
    #-----------------------------------------------------------------------
    # 1) INTERPRETATION
    #----------------------------------------------------------------------
    global explanation
    try:
        print("\n[Interpretation]")
        explanation = llm_explain(rule, INDEX_REWRITE_RULE,DATA_MESH, SECURITY_GROUPS,is_local=IS_LOCAL, chat_url=CHAT_URL, embedding_url=EMBEDDING_URL, client=client, model=MODEL, embedding_model=EMBEDDING_MODEL)
        print(explanation["text"])

        if not explanation["existSecureGroup"] and not explanation["pathExistOnDataMeshStructure"]:
            print("Skipping: invalid security group and data mesh path.")
            return
        elif not explanation["pathExistOnDataMeshStructure"]:
            print("Skipping: invalid data mesh path.")
            return
        elif not explanation["existSecureGroup"]:
            print("Skipping: invalid security group.")
            return
    except Exception as e:
        print("  (could not get explanation:", e, ")")


    #-----------------------------------------------------------------------
    # 2) EXTRACTION
    #----------------------------------------------------------------------
    print("\n[Extracting entities...]")
    try:
        entities = extract_entities(explanation["text"],INDEX_EXTRACTION, CHECK_FOR_ACTION, is_local=IS_LOCAL, chat_url=CHAT_URL, embedding_url=EMBEDDING_URL, client=client, model=MODEL, embedding_model=EMBEDDING_MODEL)
    except Exception as e:
        print("  Failed to extract_entities:", e)
        return

    #-----------------------------------------------------------------------
    # 3) REGO POLICY GENERATION
    #----------------------------------------------------------------------
    print("\n[Generating OPA policy...]")
    try:
        policy  = generate_rego_policy(entities, INDEX_BUILD_REGO, is_local=IS_LOCAL, chat_url=CHAT_URL, embedding_url=EMBEDDING_URL, client=client, model=MODEL, embedding_model=EMBEDDING_MODEL)
    except ValueError as e:
        print("  Failed to build policy:", e)
        return

    filename = f"policy_{explanation['text'][:30].replace(' ', '_')}.rego"
    filename = os.path.join(OUTPUT_REGO_DIR, filename)
    os.makedirs(OUTPUT_REGO_DIR, exist_ok=True)

    with open(filename, "w") as f:
        f.write(policy)

    print(f"Saved to: {filename}")


# --- MAIN LOOP ---
if __name__ == "__main__":
    print("=" * 50)
    print(" OPA Policy Generator — ChatGPT API")
    print(f" Loaded {len(VALID_ACTIONS)} action types from {CHECK_FOR_ACTION_PATH}")
    if IS_LOCAL:
        print("LOCAL LLM IntelIpex")
    else:
        print(f" Using model: {MODEL} and embeddings model: {EMBEDDING_MODEL}")

    print("=" * 50)

    while True:
        rule = input("\nRule: ").strip()

        if rule.lower() in ("exit", "quit"):
            break

        if rule:
            process_rule(rule)