import json
import os
import subprocess

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


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATA_MESH_DIR = os.getcwd()

LLM_DIR = os.path.join(
    DATA_MESH_DIR,
    "LLM"
)


STRUCTURE_DIR = os.path.join(
    LLM_DIR,
    "Structure"
)


CHECK_FOR_ACTION_PATH = os.path.join(
    STRUCTURE_DIR,
    "checkForAction.json"
)

SECURITY_GROUPS_PATH = os.path.join(
    STRUCTURE_DIR,
    "security_groups.json"
)

DATA_MESH_STRUCTURE_PATH = os.path.join(
    STRUCTURE_DIR,
    "data_mesh.json"
)

INPUT_STRUCTURE_PATH = os.path.join(
    STRUCTURE_DIR,
    "input.json"
)


LLM_PIPELINE_DIR = os.path.join(
    LLM_DIR,
    "LLMPipeline"
)


REGO_POLICY_CREATION_DIR = os.path.join(
    LLM_PIPELINE_DIR,
    "RegoPolicyCreation"
)


OUTPUT_REGO_DIR = os.path.join(
    REGO_POLICY_CREATION_DIR,
    "output",
    "rego_policies"
)


EXAMPLE_DIR = os.path.join(
    REGO_POLICY_CREATION_DIR,
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


DOCKER_COMPOSE_PATH = os.path.join(
    DATA_MESH_DIR,
    "docker-compose"
)


OPA_FILE_PATH = os.path.join(
    DOCKER_COMPOSE_PATH,
    "opa"
)



# ---------------------------------------------------------------------------
# Utils
# ---------------------------------------------------------------------------

def remove_duplicate_rego_default(opa_path):
    """
    Remove duplicated default allow rules from existing OPA policies.
    Keeps the first file with the default declaration.
    """

    default_found = False

    if not os.path.exists(opa_path):
        return

    for filename in sorted(os.listdir(opa_path)):

        if not filename.endswith(".rego"):
            continue

        file_path = os.path.join(
            opa_path,
            filename
        )

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as f:
            content = f.read()


        if "default allow := false" in content:

            if not default_found:
                # Keep the first default
                default_found = True
                continue


            # Remove duplicated default
            content = content.replace(
                "default allow := false\n",
                ""
            )


            content = content.replace(
                "default batchColumnMasks := []\n",
                ""
            )

            content = content.replace(
                "default rowFilters := []\n",
                ""
            )

            with open(
                file_path,
                "w",
                encoding="utf-8"
            ) as f:
                f.write(content)

            print(
                "Removed duplicated default from:",
                file_path
            )

def load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)



def restart_opa():

    try:

        subprocess.run(
            [
                "docker",
                "compose",
                "restart",
                "opa"
            ],
            cwd=DOCKER_COMPOSE_PATH,
            check=True
        )

        print("OPA restarted successfully.")


    except subprocess.CalledProcessError as e:

        print(
            f"Failed to restart OPA: {e}"
        )



# ---------------------------------------------------------------------------
# Load structure
# ---------------------------------------------------------------------------

CHECK_FOR_ACTION = load_json(
    CHECK_FOR_ACTION_PATH
)

SECURITY_GROUPS = load_json(
    SECURITY_GROUPS_PATH
)

DATA_MESH = load_json(
    DATA_MESH_STRUCTURE_PATH
)

INPUT_STRUCTURE = load_json(
    INPUT_STRUCTURE_PATH
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



INDEX_EXTRACTION, INDEX_REWRITE_RULE, INDEX_BUILD_REGO = reload_indexes(
    IS_LOCAL,
    embedding_url=EMBEDDING_URL,
    client=CLIENT,
    embedding_model=EMBEDDING_MODEL
)



VALID_ACTIONS = list(
    CHECK_FOR_ACTION.keys()
)



# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def process_rule(
    rule_passed,
    index_rewrite_rule,
    index_extraction,
    index_build_rego,
    check_for_action,
    data_mesh,
    security_group,
    input_structure,
    is_local=False,
    chat_url=None,
    embedding_url=None,
    client=None,
    model=None,
    embedding_model=None
):


    # --------------------------------------------------
    # 1) Explanation
    # --------------------------------------------------

    print("\n[Interpretation]")


    try:

        explanation = llm_explain(
            rule_passed,
            index_rewrite_rule,
            data_mesh,
            security_group,
            is_local=is_local,
            chat_url=chat_url,
            embedding_url=embedding_url,
            client=client,
            model=model,
            embedding_model=embedding_model
        )


        print(
            explanation["text"]
        )


        if not explanation.get( "existSecureGroup", False ):
            print("Skipping: invalid security group.")

            return False, None


        if not explanation.get("pathExistOnDataMeshStructure", False):

            print("Skipping: invalid data mesh path.")

            return False, None



    except Exception as e:

        print("Explanation failed:",e )

        return False, None



    # --------------------------------------------------
    # 2) Extraction
    # --------------------------------------------------

    print(
        "\n[Extracting entities...]"
    )


    try:

        entities = extract_entities(
            explanation["text"],
            index_extraction,
            check_for_action,
            is_local=is_local,
            chat_url=chat_url,
            embedding_url=embedding_url,
            client=client,
            model=model,
            embedding_model=embedding_model
        )


    except Exception as e:

        print(
            "Extraction failed:",
            e
        )

        return False, None



    # --------------------------------------------------
    # 3) Generate Rego
    # --------------------------------------------------

    print(
        "\n[Generating OPA policy...]"
    )


    try:

        policy = generate_rego_policy(
            entities,
            index_build_rego,
            input_structure,
            is_local=is_local,
            chat_url=chat_url,
            embedding_url=embedding_url,
            client=client,
            model=model,
            embedding_model=embedding_model
        )

        print(policy)

    except Exception as e:

        print(
            "Policy generation failed:",
            e
        )

        return False, None



    os.makedirs(
        OUTPUT_REGO_DIR,
        exist_ok=True
    )


    REGO_HEADER = """
package trino.authz

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false

default batchColumnMasks := []
default rowFilters := []

"""


    full_policy = (
        REGO_HEADER
        +
        policy
    )


    filename = (
        "policy_"
        +
        explanation["text"][:40]
        .replace(" ", "_")
        +
        ".rego"
    )


    output_file = os.path.join(
        OUTPUT_REGO_DIR,
        filename
    )


    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(full_policy)


    output_opa_file = os.path.join(
        OPA_FILE_PATH,
        filename
    )


    with open(
        output_opa_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(full_policy)



    print(
        "Saved policy:",
        output_file
    )


    print(
        "Updated OPA:",
        output_opa_file
    )

    # Remove old duplicated OPA defaults before adding new policy
    remove_duplicate_rego_default(OPA_FILE_PATH)

    restart_opa()


    return True, explanation



# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":


    print("=" * 50)
    print("OPA Policy Generator")
    print("=" * 50)


    while True:

        rule = input(
            "\nRule: "
        ).strip()


        if rule.lower() in (
            "exit",
            "quit"
        ):
            break


        if rule:

            process_rule(
                rule,
                INDEX_REWRITE_RULE,
                INDEX_EXTRACTION,
                INDEX_BUILD_REGO,
                CHECK_FOR_ACTION,
                DATA_MESH,
                SECURITY_GROUPS,
                INPUT_STRUCTURE,
                is_local=IS_LOCAL,
                chat_url=CHAT_URL,
                embedding_url=EMBEDDING_URL,
                client=CLIENT,
                model=MODEL,
                embedding_model=EMBEDDING_MODEL
            )