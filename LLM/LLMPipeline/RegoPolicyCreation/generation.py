import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from openai import OpenAI

from Function.LoadJson import load_json

from LLM.Interface.activate_local_llm import activate_llm
from LLM.LLMPipeline.RegoPolicyCreation.IndexCreation.index_creator import (
    reload_indexes,
)
from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.Extraction.extraction import (
     build_intermediate_representation,
)
from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.RegoRuleGeneration.build_rego import (
    generate_rego_policy,
)
from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.Rewrite.nlp_rule_rewrite import (
    llm_explain,
)

from TreePermission.tree_builder import (
    build_permission_tree_from_directory,
)

from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.Compiler.check_depth_permission import (
    compile_policy,
)


# ============================================================================
# Configuration
# ============================================================================

load_dotenv()

CHAT_URL = os.getenv(
    "CHAT_URL",
    "http://127.0.0.1:8080",
)

EMBEDDING_URL = os.getenv(
    "EMBEDDING_URL",
    "http://127.0.0.1:8081",
)

MODEL = os.getenv(
    "OPENAI_MODEL",
    "gpt-4o-mini",
)

EMBEDDING_MODEL = os.getenv(
    "EMBEDDING_MODEL",
    "text-embedding-3-small",
)

IS_LOCAL = (
    os.getenv("IS_LOCAL", "False").lower()
    == "true"
)

LOCAL_CHAT_MODEL = os.getenv(
    "LOCAL_CHAT_MODEL"
)

LOCAL_EMBEDDING_MODEL = os.getenv(
    "LOCAL_EMBEDDING_MODEL"
)

LLAMA_DIR = os.getenv(
    "LLAMA_DIR",
    r"C:\Users\berta\BertaFiles\Project\DataMeshPoliciesLLM"
    r"\LLM\LocalLLMIntelIpex"
    r"\llama-cpp-ipex-llm-2.3.0b20250424-win",
)


# ============================================================================
# Project paths
# ============================================================================

def find_project_dir() -> Path:
    current = Path.cwd().resolve()

    for directory in [current, *current.parents]:
        if directory.name == "DataMeshPoliciesLLM":
            return directory

    raise RuntimeError(
        "DataMeshPoliciesLLM folder not found."
    )


DATA_MESH_DIR = find_project_dir()

LLM_DIR = DATA_MESH_DIR / "LLM"
STRUCTURE_DIR = LLM_DIR / "Structure"

CHECK_FOR_ACTION_PATH = (
    STRUCTURE_DIR / "checkForAction.json"
)

SECURITY_GROUPS_PATH = (
    STRUCTURE_DIR / "security_groups.json"
)

DATA_MESH_STRUCTURE_PATH = (
    STRUCTURE_DIR / "data_mesh.json"
)

INPUT_STRUCTURE_PATH = (
    STRUCTURE_DIR / "input.json"
)

PERMISSION_DEPTH_PATH = (
    STRUCTURE_DIR / "permission_depth.json"
)

REGO_POLICY_CREATION_DIR = (
    LLM_DIR
    / "LLMPipeline"
    / "RegoPolicyCreation"
)

OUTPUT_REGO_DIR = (
    REGO_POLICY_CREATION_DIR
    / "output"
    / "rego_policies"
)

TREE_PERMISSION_DIR = (
    DATA_MESH_DIR
    / "TreePermission"
    / "output"
)

CANDIDATE_TREE_PATH = (
    TREE_PERMISSION_DIR
    / "_candidate_tree.json"
)

TREE_STRUCTURE_PATH = (
    TREE_PERMISSION_DIR
    / "permission_tree.json"
)

EXAMPLE_DIR = (
    REGO_POLICY_CREATION_DIR
    / "ExampleDatastore"
)

REWRITE_RULE_EXAMPLES_PATH = (
    EXAMPLE_DIR / "rewrite_rule.json"
)

EXTRACTION_EXAMPLES_PATH = (
    EXAMPLE_DIR / "extraction.json"
)

DOCKER_COMPOSE_PATH = (
    DATA_MESH_DIR / "docker-compose"
)

OPA_FILE_PATH = (
    DOCKER_COMPOSE_PATH / "opa"
)


# ============================================================================
# JSON helpers
# ============================================================================

def load_json_file(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(
            f"File not found:\n{path}"
        )

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def save_json_file(
    data: Any,
    path: Path,
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False,
        )


# ============================================================================
# OPA helpers
# ============================================================================

def remove_duplicate_rego_default(
    opa_path: Path,
) -> None:

    if not opa_path.exists():
        return

    default_found = False

    for file_path in sorted(
        opa_path.glob("*.rego")
    ):

        content = file_path.read_text(
            encoding="utf-8"
        )

        if "default allow := false" not in content:
            continue

        if not default_found:
            default_found = True
            continue

        content = content.replace(
            "default allow := false\n",
            "",
        )

        content = content.replace(
            "default batchColumnMasks := []\n",
            "",
        )

        content = content.replace(
            "default rowFilters := []\n",
            "",
        )

        file_path.write_text(
            content,
            encoding="utf-8",
        )

        print(
            "Removed duplicated defaults from:",
            file_path,
        )


def restart_opa() -> None:

    try:

        subprocess.run(
            [
                "docker",
                "compose",
                "restart",
                "opa",
            ],
            cwd=DOCKER_COMPOSE_PATH,
            check=True,
        )

        print(
            "OPA restarted successfully."
        )

    except subprocess.CalledProcessError as error:

        print(
            f"Failed to restart OPA: {error}"
        )


# ============================================================================
# New permission-tree comparison
# ============================================================================

def _subtract_permission_value(
    new_value: Any,
    old_value: Any,
) -> Optional[Any]:

    if new_value is None:
        return None

    if old_value is None:
        return json.loads(
            json.dumps(new_value)
        )

    if isinstance(new_value, list):

        if not isinstance(old_value, list):
            return json.loads(
                json.dumps(new_value)
            )

        old_items = {
            json.dumps(
                item,
                sort_keys=True,
                ensure_ascii=False,
            )
            for item in old_value
        }

        difference = []

        for item in new_value:

            key = json.dumps(
                item,
                sort_keys=True,
                ensure_ascii=False,
            )

            if key not in old_items:
                difference.append(
                    json.loads(
                        json.dumps(item)
                    )
                )

        return difference or None

    if isinstance(new_value, dict):

        if not isinstance(old_value, dict):
            return json.loads(
                json.dumps(new_value)
            )

        difference = {}

        for key, value in new_value.items():

            old_child = old_value.get(key)

            child_difference = (
                _subtract_permission_value(
                    value,
                    old_child,
                )
            )

            if child_difference is not None:
                difference[key] = child_difference

        return difference or None

    if new_value != old_value:
        return json.loads(
            json.dumps(new_value)
        )

    return None


def subtract_permission_tree(
    candidate_tree: Dict[str, Any],
    cumulative_tree: Dict[str, Any],
) -> Dict[str, Any]:

    difference = (
        _subtract_permission_value(
            candidate_tree,
            cumulative_tree,
        )
    )

    if not difference:
        return {}

    if not isinstance(
        difference,
        dict,
    ):
        return {}

    return difference


def load_cumulative_tree() -> Dict[str, Any]:

    if not TREE_STRUCTURE_PATH.exists():
        return {}

    try:

        tree = load_json_file(
            TREE_STRUCTURE_PATH
        )

        if isinstance(tree, dict):
            return tree

    except Exception as error:

        print(
            "Failed to load cumulative permission tree:",
            error,
        )

    return {}


# ============================================================================
# Build cumulative tree
# ============================================================================

def rebuild_cumulative_permission_tree() -> Dict[str, Any]:

    if not OUTPUT_REGO_DIR.exists():
        return {}

    rego_files = list(
        OUTPUT_REGO_DIR.glob("*.rego")
    )

    if not rego_files:
        return {}

    print(
        "\n[Rebuilding cumulative permission tree...]"
    )

    tree = build_permission_tree_from_directory(
        opa_directory=str(
            OUTPUT_REGO_DIR
        ),
        action_permissions_file=str(
            CHECK_FOR_ACTION_PATH
        ),
        security_groups_file=str(
            SECURITY_GROUPS_PATH
        ),
        output_file=str(
            TREE_STRUCTURE_PATH
        ),
    )

    return tree


# ============================================================================
# Generate filename
# ============================================================================

def build_policy_filename(
    explanation_text: str,
) -> str:

    safe_name = "".join(
        character
        if character.isalnum()
        or character in "_-"
        else "_"
        for character in explanation_text[:40]
    )

    safe_name = safe_name.strip("_")

    if not safe_name:
        safe_name = "policy"

    return (
        f"policy_{safe_name}.rego"
    )


# ============================================================================
# Pipeline
# ============================================================================

def process_rule(
    rule_passed,
    index_rewrite_rule,
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
    embedding_model=None,
):

    # ========================================================================
    # 1. Explanation
    # ========================================================================

    print(
        "\n[Interpretation]"
    )

    try:

        explanation = llm_explain(
            rule_passed,
            index_rewrite_rule,
            data_mesh,
            security_group,
            list(check_for_action.keys()),
            is_local=is_local,
            chat_url=chat_url,
            embedding_url=embedding_url,
            client=client,
            model=model,
            embedding_model=embedding_model,
        )

        if (
            not explanation.get(
                "existSecureGroup",
                False,
            )
            or not explanation.get(
                "pathExistOnDataMeshStructure",
                False,
            )
            or not explanation.get(
                "actionExist",
                False,
            )
        ):

            print(
                "llm_feedback:",
                explanation.get(
                    "llm_feedback",
                    "",
                ),
            )

            return False, None

        print(
            explanation["text"]
        )

    except Exception as error:

        print(
            "Explanation failed:",
            error,
        )

        return False, None

    # ========================================================================
    # 2. Extraction
    # ========================================================================

    print(
        "\n[Extracting entities...]"
    )

    try:

        entities = build_intermediate_representation(explanation, check_for_action)

    except Exception as error:

        print(
            "Extraction failed:",
            error,
        )

        return False, None

    print(
        "Extracted:"
    )

    print(
        json.dumps(
            entities,
            indent=2,
            ensure_ascii=False,
        )
    )

    # ========================================================================
    # 3. Compile permissions using permission_depth.json
    # ========================================================================

    print(
        "\n[Compiling permissions...]"
    )

    try:

        if entities is None:
            print(
                "Compilation skipped: extraction returned no entities."
            )

            return False, None

        canonical_policy = compile_policy(
            extracted_rules=[entities],
            data_mesh_file=str(
                DATA_MESH_STRUCTURE_PATH
            ),
            permission_depth_file=str(
                PERMISSION_DEPTH_PATH
            ),
        )

    except Exception as error:

        print(
            "Permission compilation failed:",
            error,
        )

        return False, None

    print(
        "\n[Canonical policy]"
    )

    print(
        json.dumps(
            canonical_policy,
            indent=2,
            ensure_ascii=False,
        )
    )






#     # ========================================================================
#     # 3. Generate Rego
#     # ========================================================================
#
#     print(
#         "\n[Generating OPA policy...]"
#     )
#
#     try:
#
#         policy = generate_rego_policy(
#             entities,
#             index_build_rego,
#             input_structure,
#             is_local=is_local,
#             chat_url=chat_url,
#             embedding_url=embedding_url,
#             client=client,
#             model=model,
#             embedding_model=embedding_model,
#         )
#
#     except Exception as error:
#
#         print(
#             "Policy generation failed:",
#             error,
#         )
#
#         return False, None
#
#     # ========================================================================
#     # 4. Prepare directories
#     # ========================================================================
#
#     OUTPUT_REGO_DIR.mkdir(
#         parents=True,
#         exist_ok=True,
#     )
#
#     TREE_PERMISSION_DIR.mkdir(
#         parents=True,
#         exist_ok=True,
#     )
#
#     OPA_FILE_PATH.mkdir(
#         parents=True,
#         exist_ok=True,
#     )
#
#     # ========================================================================
#     # 5. Complete Rego policy
#     # ========================================================================
#
#     REGO_HEADER = """
# package trino.authz
#
# import future.keywords.in
# import future.keywords.if
# import future.keywords.contains
#
# default allow := false
#
# default batchColumnMasks := []
# default rowFilters := []
#
# """
#
#     full_policy = (
#         REGO_HEADER
#         + policy
#     )
#
#     # ========================================================================
#     # 6. Generate filename
#     # ========================================================================
#
#     filename = build_policy_filename(
#         explanation["text"]
#     )
#
#     output_file = (
#         OUTPUT_REGO_DIR / filename
#     )
#
#     output_opa_file = (
#         OPA_FILE_PATH / filename
#     )
#
#     # ========================================================================
#     # 7. Write candidate Rego
#     # ========================================================================
#
#     output_file.write_text(
#         full_policy,
#         encoding="utf-8",
#     )
#
#     print(
#         "\nGenerated candidate policy:",
#         output_file,
#     )
#
#     # ========================================================================
#     # 8. Build candidate permission tree
#     # ========================================================================
#
#     print(
#         "\n[Building candidate permission tree...]"
#     )
#
#     try:
#
#         candidate_tree = build_permission_tree_from_directory(
#             opa_directory=str(
#                 OUTPUT_REGO_DIR
#             ),
#             action_permissions_file=str(
#                 CHECK_FOR_ACTION_PATH
#             ),
#             security_groups_file=str(
#                 SECURITY_GROUPS_PATH
#             ),
#         )
#
#     except Exception as error:
#
#         print(
#             "Failed to build candidate permission tree:",
#             error,
#         )
#
#         output_file.unlink(
#             missing_ok=True
#         )
#
#         return False, None
#
#     save_json_file(
#         candidate_tree,
#         CANDIDATE_TREE_PATH,
#     )
#
#     print(
#         "\nCandidate permission tree:"
#     )
#
#     print(
#         json.dumps(
#             candidate_tree,
#             indent=2,
#             ensure_ascii=False,
#         )
#     )
#
#     # ========================================================================
#     # 9. Load cumulative tree
#     # ========================================================================
#
#     print(
#         "\n[Checking existing permissions...]"
#     )
#
#     cumulative_tree = (
#         load_cumulative_tree()
#     )
#
#     difference_tree = (
#         subtract_permission_tree(
#             candidate_tree,
#             cumulative_tree,
#         )
#     )
#
#     print(
#         "\n[Permission difference]"
#     )
#
#     print(
#         json.dumps(
#             difference_tree,
#             indent=2,
#             ensure_ascii=False,
#         )
#     )
#
#     # ========================================================================
#     # 10. No new permissions
#     # ========================================================================
#
#     if not difference_tree:
#
#         print(
#             "\nNo new permissions found."
#         )
#
#         print(
#             "Generated policy is already represented "
#             "by the cumulative permission tree."
#         )
#
#         output_file.unlink(
#             missing_ok=True
#         )
#
#         CANDIDATE_TREE_PATH.unlink(
#             missing_ok=True
#         )
#
#         return True, explanation
#
#     # ========================================================================
#     # 11. New permissions found
#     # ========================================================================
#
#     print(
#         "\nNew permissions detected:"
#     )
#
#     print(
#         json.dumps(
#             difference_tree,
#             indent=2,
#             ensure_ascii=False,
#         )
#     )
#
#     # ========================================================================
#     # 12. Copy same policy to OPA
#     # ========================================================================
#
#     output_opa_file.write_text(
#         full_policy,
#         encoding="utf-8",
#     )
#
#     print(
#         "\nUpdated OPA:",
#         output_opa_file,
#     )
#
#     # ========================================================================
#     # 13. Rebuild cumulative permission tree
#     # ========================================================================
#
#     try:
#
#         complete_tree = (
#             rebuild_cumulative_permission_tree()
#         )
#
#     except Exception as error:
#
#         print(
#             "Failed to rebuild cumulative permission tree:",
#             error,
#         )
#
#         return False, None
#
#     print(
#         "\n[Cumulative permission tree]"
#     )
#
#     print(
#         json.dumps(
#             complete_tree,
#             indent=2,
#             ensure_ascii=False,
#         )
#     )
#
#     print(
#         "\nSaved cumulative tree:",
#         TREE_STRUCTURE_PATH,
#     )
#
#     # ========================================================================
#     # 14. Remove candidate tree
#     # ========================================================================
#
#     CANDIDATE_TREE_PATH.unlink(
#         missing_ok=True
#     )
#
#     # ========================================================================
#     # 15. Remove duplicated OPA defaults
#     # ========================================================================
#
#     remove_duplicate_rego_default(
#         OPA_FILE_PATH
#     )
#
#     # ========================================================================
#     # 16. Restart OPA
#     # ========================================================================
#
#     restart_opa()
#
#     return True, explanation


# ============================================================================
# Initialization
# ============================================================================

def initialize_llm():

    client = OpenAI(
        api_key=os.getenv(
            "OPENAI_API_KEY"
        )
    )

    activate_llm(
        LLAMA_DIR,
        IS_LOCAL,
        CHAT_URL,
        LOCAL_CHAT_MODEL,
        "8080",
    )

    activate_llm(
        LLAMA_DIR,
        IS_LOCAL,
        EMBEDDING_URL,
        LOCAL_EMBEDDING_MODEL,
        "8081",
        other_params=" --embedding",
    )

    return client


# ============================================================================
# Main
# ============================================================================

def main():

    print(
        "=" * 70
    )

    print(
        "OPA POLICY GENERATOR"
    )

    print(
        "=" * 70
    )

    print(
        f"Project root:       {DATA_MESH_DIR}"
    )

    print(
        f"Data mesh:          {DATA_MESH_STRUCTURE_PATH}"
    )

    print(
        f"Security groups:    {SECURITY_GROUPS_PATH}"
    )

    print(
        f"Check actions:      {CHECK_FOR_ACTION_PATH}"
    )

    print(
        f"OPA directory:      {OPA_FILE_PATH}"
    )

    print(
        f"Generated policies: {OUTPUT_REGO_DIR}"
    )

    print(
        f"Permission tree:    {TREE_STRUCTURE_PATH}"
    )

    # ------------------------------------------------------------------------
    # Load structures
    # ------------------------------------------------------------------------

    check_for_action = load_json(
        CHECK_FOR_ACTION_PATH
    )

    security_groups = load_json(
        SECURITY_GROUPS_PATH
    )

    data_mesh = load_json(
        DATA_MESH_STRUCTURE_PATH
    )

    input_structure = load_json(
        INPUT_STRUCTURE_PATH
    )

    # ------------------------------------------------------------------------
    # LLM
    # ------------------------------------------------------------------------

    client = initialize_llm()

    (
        index_rewrite_rule,
        index_build_rego,
    ) = reload_indexes(
        IS_LOCAL,
        embedding_url=EMBEDDING_URL,
        client=client,
        embedding_model=EMBEDDING_MODEL,
    )

    # ------------------------------------------------------------------------
    # Interactive loop
    # ------------------------------------------------------------------------

    while True:

        rule = input(
            "\nRule: "
        ).strip()

        if rule.lower() in (
            "exit",
            "quit",
        ):
            break

        if not rule:
            continue

        process_rule(
            rule_passed=rule,
            index_rewrite_rule=index_rewrite_rule,
            index_build_rego=index_build_rego,
            check_for_action=check_for_action,
            data_mesh=data_mesh,
            security_group=security_groups,
            input_structure=input_structure,
            is_local=IS_LOCAL,
            chat_url=CHAT_URL,
            embedding_url=EMBEDDING_URL,
            client=client,
            model=MODEL,
            embedding_model=EMBEDDING_MODEL,
        )


if __name__ == "__main__":
    main()