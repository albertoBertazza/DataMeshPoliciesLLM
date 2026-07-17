import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from LLM.Interface.activate_local_llm import activate_llm
from LLM.LLMPipeline.Evaluation.evaluate import evaluate_test
from LLM.LLMPipeline.RegoPolicyCreation.IndexCreation.index_creator import reload_indexes
from LLM.LLMPipeline.RegoPolicyCreation.generation import process_rule
from LLM.LLMPipeline.TrinoTestInteraction.test_generator import generate_test
from Tester.run_test_trino import launch_test


# ==========================================================
# LLM CONFIG
# ==========================================================

CHAT_URL = "http://127.0.0.1:8080"
EMBEDDING_URL = "http://127.0.0.1:8081"

load_dotenv()

CLIENT = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

MODEL = os.getenv(
    "OPENAI_MODEL",
    "gpt-4o-mini"
)

EMBEDDING_MODEL = "text-embedding-3-small"

IS_LOCAL = os.getenv(
    "IS_LOCAL",
    "False"
) == "True"



# ==========================================================
# PATHS
# ==========================================================

DATA_MESH_DIR = os.getcwd()

LLM_DIR = os.path.join(
    DATA_MESH_DIR,
    "LLM"
)


STRUCTURE_DIR = os.path.join(
    LLM_DIR,
    "Structure"
)


USER_CREDENTIALS_PATH = os.path.join(
    STRUCTURE_DIR,
    "user_credentials.json"
)

CHECK_FOR_ACTION_PATH = os.path.join(
    STRUCTURE_DIR,
    "checkForAction.json"
)

INPUT_SCHEMA_PATH = os.path.join(
    STRUCTURE_DIR,
    "input.json"
)

SECURITY_GROUPS_PATH = os.path.join(
    STRUCTURE_DIR,
    "security_groups.json"
)

DATA_MESH_STRUCTURE_PATH = os.path.join(
    STRUCTURE_DIR,
    "data_mesh.json"
)



REGO_DIR = os.path.join(
    LLM_DIR,
    "LLMPipeline",
    "RegoPolicyCreation"
)


EXAMPLE_DIR = os.path.join(
    REGO_DIR,
    "ExampleDatastore"
)


REWRITE_RULE_EXAMPLES_PATH = os.path.join(
    EXAMPLE_DIR,
    "rewrite_rule.json"
)


EXTRACTION_EXAMPLES_PATH = os.path.join(
    EXAMPLE_DIR,
    "extraction.json"
)



TRINO_TEST_DIR = os.path.join(
    LLM_DIR,
    "LLMPipeline",
    "TrinoTestInteraction"
)


TEST_INDEX_DIR = TRINO_TEST_DIR



EVALUATION_DIR = os.path.join(
    LLM_DIR,
    "LLMPipeline",
    "Evaluation"
)


EVALUATION_EXAMPLES_PATH = os.path.join(
    EVALUATION_DIR,
    "Examples",
    "evaluation_examples.json"
)



DOCKER_COMPOSE_PATH = os.path.join(
    DATA_MESH_DIR,
    "docker-compose"
)


POLICY_PATH = os.path.join(
    DOCKER_COMPOSE_PATH,
    "opa",
    "policy.rego"
)



# ==========================================================
# UTILS
# ==========================================================

def load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)



# ==========================================================
# LOAD STRUCTURE
# ==========================================================

CHECK_FOR_ACTION = load_json(
    CHECK_FOR_ACTION_PATH
)

INPUT_SCHEMA = load_json(
    INPUT_SCHEMA_PATH
)

SECURITY_GROUPS = load_json(
    SECURITY_GROUPS_PATH
)

DATA_MESH = load_json(
    DATA_MESH_STRUCTURE_PATH
)

USER_CREDENTIALS = load_json(
    USER_CREDENTIALS_PATH
)



# ==========================================================
# LOCAL LLM
# ==========================================================

LLAMA_DIR = r"C:\Users\berta\BertaFiles\Project\DataMeshPoliciesLLM\LLM\LocalLLMIntelIpex\llama-cpp-ipex-llm-2.3.0b20250424-win"


LOCAL_CHAT_MODEL = os.getenv(
    "LOCAL_CHAT_MODEL"
)

LOCAL_EMBEDDING_MODEL = os.getenv(
    "LOCAL_EMBEDDING_MODEL"
)


activate_llm(
    LLAMA_DIR,
    IS_LOCAL,
    CHAT_URL,
    LOCAL_CHAT_MODEL,
    "8080"
)


activate_llm(
    LLAMA_DIR,
    IS_LOCAL,
    EMBEDDING_URL,
    LOCAL_EMBEDDING_MODEL,
    "8081",
    other_params=" --embedding"
)



# ==========================================================
# INDEXES
# ==========================================================

INDEX_EXTRACTION, INDEX_REWRITE_RULE, INDEX_BUILD_REGO = reload_indexes(
    IS_LOCAL,
    embedding_url=EMBEDDING_URL,
    client=CLIENT,
    embedding_model=EMBEDDING_MODEL
)


INDEX_TEST_CREATION = reload_indexes(
    IS_LOCAL,
    embedding_url=EMBEDDING_URL,
    client=CLIENT,
    embedding_model=EMBEDDING_MODEL
)



# ==========================================================
# PIPELINE
# ==========================================================

if __name__ == "__main__":

    print("=" * 60)
    print(" DATA MESH POLICY PIPELINE")
    print("=" * 60)


    while True:

        rule = input(
            "\nRule: "
        ).strip()


        if rule.lower() in (
            "exit",
            "quit"
        ):
            break


        if not rule:
            continue



        # -------------------------------
        # Generate OPA policy
        # -------------------------------

        result, explanation = process_rule(
            rule,
            INDEX_REWRITE_RULE,
            INDEX_EXTRACTION,
            INDEX_BUILD_REGO,
            CHECK_FOR_ACTION,
            DATA_MESH,
            SECURITY_GROUPS,
            is_local=IS_LOCAL,
            chat_url=CHAT_URL,
            embedding_url=EMBEDDING_URL,
            client=CLIENT,
            model=MODEL,
            embedding_model=EMBEDDING_MODEL
        )


        if not result:
            continue



        # -------------------------------
        # Generate Trino tests
        # -------------------------------

        generate_test(
            explanation,
            data_mesh=DATA_MESH,
            user_credentials=USER_CREDENTIALS,
            test_creation_example_indexes=INDEX_TEST_CREATION,
            is_local=IS_LOCAL,
            chat_url=CHAT_URL,
            embedding_url=EMBEDDING_URL,
            client=CLIENT,
            model=MODEL,
            embedding_model=EMBEDDING_MODEL
        )



        # -------------------------------
        # Execute Trino tests
        # -------------------------------

        launch_test()



        # -------------------------------
        # Evaluate results
        # -------------------------------

        evaluate_test(
            data_mesh=DATA_MESH,
            users=USER_CREDENTIALS,
            actions=CHECK_FOR_ACTION,
            policy_path=POLICY_PATH,
            examples_path=EVALUATION_EXAMPLES_PATH,
            is_local=IS_LOCAL,
            chat_url=CHAT_URL,
            client=CLIENT,
            model=MODEL
        )