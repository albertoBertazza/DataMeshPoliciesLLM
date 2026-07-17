import json
import os
from dotenv import load_dotenv
from openai import OpenAI

from LLM.Interface.activate_local_llm import activate_llm
from LLM.LLMPipeline.TrinoTestInteraction.IndexCreation.index_creator import reload_indexes
from LLM.LLMPipeline.TrinoTestInteraction.Pipeline.Interaction.trino_test_interaction import (
    create_trino_tests,
)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CHAT_URL = "http://127.0.0.1:8080"
EMBEDDING_URL = "http://127.0.0.1:8081"

load_dotenv()

CLIENT = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

MODEL = os.environ.get(
    "OPENAI_MODEL",
    "gpt-4o-mini"
)

EMBEDDING_MODEL = "text-embedding-3-small"

IS_LOCAL = os.getenv(
    "IS_LOCAL",
    "False"
) == "True"



# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATA_MESH_DIR = os.getcwd()

while os.path.basename(DATA_MESH_DIR) != "DataMeshPoliciesLLM":
    parent = os.path.dirname(DATA_MESH_DIR)

    if parent == DATA_MESH_DIR:
        raise RuntimeError(
            "DataMeshPoliciesLLM folder not found"
        )

    DATA_MESH_DIR = parent


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


TRINO_TEST_DIR = os.path.join(
    LLM_DIR,
    "LLMPipeline",
    "TrinoTestInteraction"
)


OUTPUT_TESTS_DIR = os.path.join(
    TRINO_TEST_DIR,
    "output",
    "generated_tests"
)


DATA_MESH_PATH = os.path.join(
    STRUCTURE_DIR,
    "data_mesh.json"
)

TEST_INPUT_DIR = os.path.join(
    DATA_MESH_DIR,
    "Tester",
    "tests"
)



def load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)



USER_CREDENTIALS = load_json(
    USER_CREDENTIALS_PATH
)

DATA_MESH = load_json(
    DATA_MESH_PATH
)


# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------

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



INDEX_TEST_CREATION = reload_indexes(
    IS_LOCAL,
    embedding_url=EMBEDDING_URL,
    client=CLIENT,
    embedding_model=EMBEDDING_MODEL,
)



# ---------------------------------------------------------------------------
# Generate tests
# ---------------------------------------------------------------------------

def generate_test(
    rule_explanation,
    data_mesh,
    user_credentials,
    test_creation_example_indexes,
    is_local,
    chat_url=None,
    embedding_url=None,
    client=None,
    model=None,
    embedding_model=None
):

    print("=" * 50)
    print(" Trino Interaction Test Generator")

    if is_local:
        print("LOCAL LLM IntelIpex")
    else:
        print(f"Using model: {model}")

    print("=" * 50)


    print("\n[Generating Trino interaction tests...]")

    print(rule_explanation)


    if isinstance(rule_explanation, dict):

        rule_text = rule_explanation.get(
            "text",
            ""
        )


    elif isinstance(rule_explanation, list):

        rule_text = ""

        for item in rule_explanation:

            if isinstance(item, dict) and "text" in item:
                rule_text = item["text"]
                break

        if not rule_text:
            rule_text = json.dumps(
                rule_explanation
            )


    else:

        rule_text = str(rule_explanation)



    try:

        tests = create_trino_tests(
            rule_explanation=rule_text,
            data_mesh=data_mesh,
            user_credentials=user_credentials,
            test_creation_example_indexes=test_creation_example_indexes,
            is_local=is_local,
            chat_url=chat_url,
            embedding_url=embedding_url,
            client=client,
            model=model,
            embedding_model=embedding_model,
        )

        # Keep only the "output" section
        if isinstance(tests, dict):
            tests = tests.get("output", tests)




    except Exception as e:

        print(
            "Failed to generate tests:",
            e
        )

        return None



    os.makedirs(
        OUTPUT_TESTS_DIR,
        exist_ok=True
    )


    safe_name = "".join(
        c if c.isalnum() or c in "_-" else "_"
        for c in rule_text[:40]
    )


    filename = os.path.join(
        OUTPUT_TESTS_DIR,
        f"tests_{safe_name}.json"
    )


    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            tests,
            f,
            indent=2
        )


    print(
        f"Saved: {filename}"
    )



    os.makedirs(
        TEST_INPUT_DIR,
        exist_ok=True
    )


    test_file = os.path.join(
        TEST_INPUT_DIR,
        "tests.json"
    )


    with open(
        test_file,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            tests,
            f,
            indent=2
        )


    print(
        f"Overwrite tests: {test_file}"
    )


    return tests



# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    while True:

        rule = input(
            "\nRule explanation: "
        ).strip()


        if rule.lower() in (
            "exit",
            "quit"
        ):
            break


        if rule:

            generate_test(
                rule,
                DATA_MESH,
                USER_CREDENTIALS,
                INDEX_TEST_CREATION,
                IS_LOCAL,
                CHAT_URL,
                EMBEDDING_URL,
                CLIENT,
                MODEL,
                EMBEDDING_MODEL
            )