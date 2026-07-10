import json
import os

from openai import OpenAI
from dotenv import load_dotenv

from IndexCreation.index_creator import reload_indexes
from Pipeline.Rewrite.nlp_rule_rewrite import llm_explain
from Pipeline.Extraction.extraction import extract_entities
from Pipeline.RegoRuleGeneration.build_rego import generate_rego_policy

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# LOCAL LLM
URL = "http://127.0.0.1:8080/completion"
# REMOTE LLM
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
EMBEDDING_MODEL ="text-embedding-3-small"

# WHICH LLM TO USE
IS_LOCAL=os.getenv("IS_LOCAL")



LLM_DIR = os.getenv("LLM_DIR")

STRUCTURE_DIR = os.path.join(LLM_DIR, "Structure")

CHECK_FOR_ACTION_PATH = os.path.join(STRUCTURE_DIR, "checkForAction.json")
INPUT_SCHEMA_PATH = os.path.join(STRUCTURE_DIR, "input.json")
SECURITY_GROUPS_PATH=os.path.join(STRUCTURE_DIR, "security_groups.json")

EXAMPLE_DIR = os.path.join(LLM_DIR, "ExampleDatastore")

REWRITE_RULE_EXAMPLES_PATH = os.path.join(EXAMPLE_DIR, "rewrite_rule.json")
EXTRACTION_EXAMPLES_PATH = os.path.join(EXAMPLE_DIR, "extraction.json")




def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Loaded once at startup - these are the two files you already have
CHECK_FOR_ACTION = load_json(CHECK_FOR_ACTION_PATH)   # action -> [checks...]
INPUT_SCHEMA = load_json(INPUT_SCHEMA_PATH)           # shape Trino sends to OPA
SECURITY_GROUPS = load_json(SECURITY_GROUPS_PATH)

INDEX_EXTRACTION, INDEX_REWRITE_RULE, INDEX_BUILD_REGO = reload_indexes(IS_LOCAL,url=URL, client=client, embedding_model=EMBEDDING_MODEL)

VALID_ACTIONS = list(CHECK_FOR_ACTION.keys())






# ---------------------------------------------------------------------------
# Extraction / interpretation
# ---------------------------------------------------------------------------




def process_rule(rule):
    #-----------------------------------------------------------------------
    # 1) INTERPRETATION
    #----------------------------------------------------------------------
    global explanation
    try:
        print("\n[Interpretation]")
        explanation = llm_explain(rule, INDEX_REWRITE_RULE,is_local=IS_LOCAL, url=URL, client=client, model=MODEL, embedding_model=EMBEDDING_MODEL)
        print(explanation)
    except Exception as e:
        print("  (could not get explanation:", e, ")")


    #-----------------------------------------------------------------------
    # 2) EXTRACTION
    #----------------------------------------------------------------------
    print("\n[Extracting entities...]")
    try:
        entities = extract_entities(explanation, CHECK_FOR_ACTION, INDEX_EXTRACTION, SECURITY_GROUPS, is_local=IS_LOCAL, url=URL, client=client, model=MODEL, embedding_model=EMBEDDING_MODEL)
    except Exception as e:
        print("  Failed to parse entities:", e)
        return

    #-----------------------------------------------------------------------
    # 3) REGO POLICY GENERATION
    #----------------------------------------------------------------------
    print("\n[Generating OPA policy...]")
    try:
        policy  = generate_rego_policy(entities, INDEX_BUILD_REGO, is_local=IS_LOCAL, url=URL, client=client, model=MODEL, embedding_model=EMBEDDING_MODEL)
    except ValueError as e:
        print("  Failed to build policy:", e)
        return

    output_dir = "output/rego_policies"
    filename = f"policy_{explanation[:30].replace(' ', '_')}.rego"
    filename = os.path.join(output_dir, filename)

    os.makedirs(output_dir, exist_ok=True)

    with open(filename, "w") as f:
        f.write(policy)

    print(f"Saved to: {filename}")


# --- MAIN LOOP ---
if __name__ == "__main__":
    print("=" * 50)
    print(" OPA Policy Generator — ChatGPT API")
    print(f" Loaded {len(VALID_ACTIONS)} action types from {CHECK_FOR_ACTION_PATH}")
    print(f" Using model: {MODEL}")
    print("=" * 50)

    if IS_LOCAL=='True':
        IS_LOCAL=True
    else:
        IS_LOCAL=False
    print("IS_LOCAL : ", IS_LOCAL)


    while True:
        rule = input("\nRule: ").strip()

        if rule.lower() in ("exit", "quit"):
            break

        if rule:
            process_rule(rule)