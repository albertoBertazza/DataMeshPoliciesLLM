import json
import os
import time
import subprocess
import requests
from dotenv import load_dotenv
from openai import OpenAI

from LLMPipeline.TrinoTestInteraction.IndexCreation.index_creator import reload_indexes
from LLMPipeline.TrinoTestInteraction.Pipeline.Interaction.trino_test_interaction import (
    create_trino_tests,
)

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
EMBEDDING_MODEL = "text-embedding-3-small"

# WHICH LLM TO USE
IS_LOCAL = os.getenv("IS_LOCAL", "False") == "True"

current = os.getcwd()

while os.path.basename(current) != "LLM":
    parent = os.path.dirname(current)

    if parent == current:
        raise RuntimeError("LLM folder not found")

    current = parent

LLM_DIR = current
print(LLM_DIR)

while os.path.basename(current) != "DataMeshPoliciesLLM":
    parent = os.path.dirname(current)

    if parent == current:
        raise RuntimeError("DataMeshPoliciesLLM folder not found")

    current = parent

DATA_MESH_DIR = current
print("dataMeshDir: ", DATA_MESH_DIR)

STRUCTURE_DIR = os.path.join(LLM_DIR, "Structure")
USER_CREDENTIALS_PATH = os.path.join(STRUCTURE_DIR, "user_credentials.json")

LLM_PIPELINE_DIR = os.path.join(LLM_DIR, "LLMPipeline")
TRINO_TEST_DIR = os.path.join(LLM_PIPELINE_DIR, "TrinoTestInteraction")

OUTPUT_DIR = os.path.join(TRINO_TEST_DIR, "output")
OUTPUT_TESTS_DIR = os.path.join(OUTPUT_DIR, "generated_tests")

TEST_DIR = os.path.join(DATA_MESH_DIR, "Tester")
TEST_INPUT_DIR = os.path.join(TEST_DIR, "tests")


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


USER_CREDENTIALS = load_json(USER_CREDENTIALS_PATH)


def wait_for_llm(url, timeout=120):
    print("Waiting for local LLM server...")
    start = time.time()

    while time.time() - start < timeout:
        try:
            r = requests.get(url + "/health")
            if r.status_code == 200:
                print("LLM server ready")
                return True
        except requests.exceptions.ConnectionError:
            pass

        time.sleep(2)

    raise RuntimeError("LLM server did not start within timeout")


if IS_LOCAL:
    LLAMA_DIR = r"C:\Users\berta\BertaFiles\Project\DataMeshPoliciesLLM\LLM\RegoPolicyCreation\LocalLLMIntelIpex\llama-cpp-ipex-llm-2.3.0b20250424-win"

    subprocess.Popen(
        [
            "powershell.exe",
            "-NoExit",
            "-Command",
            fr'''
cd "{LLAMA_DIR}"
.\llama-server.exe -m .\models\Qwen2.5.1-Coder-7B-Instruct-Q4_K_M.gguf --port 8080
'''
        ],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )

    wait_for_llm(CHAT_URL)

    subprocess.Popen(
        [
            "powershell.exe",
            "-NoExit",
            "-Command",
            fr'''
cd "{LLAMA_DIR}"
.\llama-server.exe -m .\models\nomic-embed-text-v1.5.f16.gguf --embedding --port 8081
'''
        ],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )

    wait_for_llm(EMBEDDING_URL)


INDEX_TEST_CREATION = reload_indexes(
    IS_LOCAL,
    embedding_url=EMBEDDING_URL,
    client=client,
    embedding_model=EMBEDDING_MODEL,
)


def process_rule(rule_explanation):

    print("\n[Generating Trino interaction tests...]")

    try:
        tests = create_trino_tests(
            rule_explanation=rule_explanation,
            user_credentials=USER_CREDENTIALS,
            test_creation_example_indexes=INDEX_TEST_CREATION,
            is_local=IS_LOCAL,
            chat_url=CHAT_URL,
            embedding_url=EMBEDDING_URL,
            client=client,
            model=MODEL,
            embedding_model=EMBEDDING_MODEL,
        )

    except Exception as e:
        print("Failed to generate tests:", e)
        return

    os.makedirs(OUTPUT_TESTS_DIR, exist_ok=True)

    safe_name = "".join(
        c if c.isalnum() or c in "_-" else "_"
        for c in rule_explanation[:40]
    )

    filename = os.path.join(
        OUTPUT_TESTS_DIR,
        f"tests_{safe_name}.json",
    )


    with open(filename, "w", encoding="utf-8") as f:
        json.dump(tests, f, indent=2)

    print(f"Saved to: {filename}")

    # overwrite the tests file:
    os.makedirs(TEST_INPUT_DIR, exist_ok=True)

    test_file_name= os.path.join(TEST_INPUT_DIR, f"tests.json")

    with open(test_file_name, "w", encoding="utf-8") as f:
        json.dump(tests, f, indent=2)

    print(f"Overwrite the tests file: {test_file_name}")





if __name__ == "__main__":

    print("=" * 50)
    print(" Trino Interaction Test Generator")
    if IS_LOCAL:
        print("LOCAL LLM IntelIpex")
    else:
        print(f"Using model: {MODEL}")
    print("=" * 50)

    while True:

        rule = input("\nRule explanation: ").strip()

        if rule.lower() in ("exit", "quit"):
            break

        if rule:
            process_rule(rule)