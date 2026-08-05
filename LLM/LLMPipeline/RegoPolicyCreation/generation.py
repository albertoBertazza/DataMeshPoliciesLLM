import json
import os
import subprocess

from dotenv import load_dotenv
from openai import OpenAI

from Function.LoadJson import load_json

from LLM.Interface.activate_local_llm import activate_llm
from LLM.LLMPipeline.RegoPolicyCreation.IndexCreation.index_creator import reload_indexes
from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.Extraction.extraction import extract_entities
from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.RegoRuleGeneration.build_rego import generate_rego_policy
from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.RegoRuleGeneration.tree_helper.tree_helper import (
    build_complete_permission_tree,
)
from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.Rewrite.nlp_rule_rewrite import llm_explain
from TreePermission.TreeBuilder import build_permission_tree


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

TREE_PERMISSION_DIR = os.path.join(
    REGO_POLICY_CREATION_DIR,
    "output",
    "tree_permission"
)

TREE_STRUCTURE_PATH = os.path.join(
    TREE_PERMISSION_DIR,
    "tree_structure.json"
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


# ============================================================================
# Utility functions
# ============================================================================

def remove_duplicate_rego_default(opa_path):
    """
    Remove duplicated default declarations from existing OPA policies.

    Keeps the first file containing the defaults and removes duplicated
    declarations from subsequent files.
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

        if "default allow := false" not in content:
            continue

        if not default_found:

            default_found = True

            continue

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

        print(
            "OPA restarted successfully."
        )

    except subprocess.CalledProcessError as e:

        print(
            f"Failed to restart OPA: {e}"
        )


# ============================================================================
# FIX:
# Deterministic permission extraction from a permission tree
# ============================================================================

def _extract_permission_entries(tree):
    """
    Convert a permission tree into a set of explicit permission entries.

    Each entry contains the complete permission path:

        subject
        catalog
        schema
        table
        column
        permission

    This function deliberately does NOT use wildcards.

    Example:

        {
            "subject": "finance_manager",
            "catalog": "iceberg",
            "schema": "finance",
            "table": "employee_finance",
            "column": "",
            "permission": "UpdateTableColumns"
        }
    """

    entries = set()

    if not isinstance(tree, dict):
        return entries

    for subject, subject_data in tree.items():

        if not isinstance(subject_data, dict):
            continue

        # ------------------------------------------------------------
        # Subject-level permissions
        # ------------------------------------------------------------

        subject_permissions = subject_data.get(
            "permission",
            []
        )

        if isinstance(subject_permissions, list):

            for permission in subject_permissions:

                if permission:

                    entries.add(
                        (
                            subject,
                            "",
                            "",
                            "",
                            "",
                            permission
                        )
                    )

        # ------------------------------------------------------------
        # Catalogs
        # ------------------------------------------------------------

        catalogs = subject_data.get(
            "catalogs",
            []
        )

        if not isinstance(catalogs, list):
            continue

        for catalog_data in catalogs:

            if not isinstance(catalog_data, dict):
                continue

            catalog_name = catalog_data.get(
                "catalog",
                ""
            )

            catalog_permissions = catalog_data.get(
                "permission",
                []
            )

            if isinstance(
                catalog_permissions,
                list
            ):

                for permission in catalog_permissions:

                    if permission:

                        entries.add(
                            (
                                subject,
                                catalog_name,
                                "",
                                "",
                                "",
                                permission
                            )
                        )

            # --------------------------------------------------------
            # Schemas
            # --------------------------------------------------------

            schemas = catalog_data.get(
                "schemas",
                []
            )

            if not isinstance(schemas, list):
                continue

            for schema_data in schemas:

                if not isinstance(schema_data, dict):
                    continue

                schema_name = schema_data.get(
                    "schema",
                    ""
                )

                schema_permissions = schema_data.get(
                    "permission",
                    []
                )

                if isinstance(
                    schema_permissions,
                    list
                ):

                    for permission in schema_permissions:

                        if permission:

                            entries.add(
                                (
                                    subject,
                                    catalog_name,
                                    schema_name,
                                    "",
                                    "",
                                    permission
                                )
                            )

                # ----------------------------------------------------
                # Tables
                # ----------------------------------------------------

                tables = schema_data.get(
                    "tables",
                    []
                )

                if not isinstance(tables, list):
                    continue

                for table_data in tables:

                    if not isinstance(
                        table_data,
                        dict
                    ):
                        continue

                    table_name = table_data.get(
                        "table",
                        ""
                    )

                    table_permissions = table_data.get(
                        "permission",
                        []
                    )

                    if isinstance(
                        table_permissions,
                        list
                    ):

                        for permission in table_permissions:

                            if permission:

                                entries.add(
                                    (
                                        subject,
                                        catalog_name,
                                        schema_name,
                                        table_name,
                                        "",
                                        permission
                                    )
                                )

                    # ------------------------------------------------
                    # Columns
                    # ------------------------------------------------

                    columns = table_data.get(
                        "columns",
                        []
                    )

                    if not isinstance(
                        columns,
                        list
                    ):
                        continue

                    for column_data in columns:

                        if not isinstance(
                            column_data,
                            dict
                        ):
                            continue

                        column_name = column_data.get(
                            "column",
                            ""
                        )

                        column_permissions = column_data.get(
                            "permission",
                            []
                        )

                        if not isinstance(
                            column_permissions,
                            list
                        ):
                            continue

                        for permission in column_permissions:

                            if permission:

                                entries.add(
                                    (
                                        subject,
                                        catalog_name,
                                        schema_name,
                                        table_name,
                                        column_name,
                                        permission
                                    )
                                )

    return entries


def _permission_entries_to_tree(entries):
    """
    Convert permission entries back into the same tree-style structure.

    This is used only for displaying the difference.

    No wildcard "*" is generated.
    """

    result = {}

    # ------------------------------------------------------------
    # Sort for deterministic output
    # ------------------------------------------------------------

    for (
        subject,
        catalog_name,
        schema_name,
        table_name,
        column_name,
        permission
    ) in sorted(entries):

        if subject not in result:

            result[subject] = {
                "permission": [],
                "filters": None,
                "catalogs": []
            }

        subject_node = result[subject]

        # --------------------------------------------------------
        # Subject permission
        # --------------------------------------------------------

        if not catalog_name:

            if permission not in subject_node["permission"]:

                subject_node["permission"].append(
                    permission
                )

            continue

        # --------------------------------------------------------
        # Catalog
        # --------------------------------------------------------

        catalog_node = None

        for item in subject_node["catalogs"]:

            if item.get("catalog") == catalog_name:

                catalog_node = item
                break

        if catalog_node is None:

            catalog_node = {
                "catalog": catalog_name,
                "permission": [],
                "filters": None,
                "schemas": []
            }

            subject_node["catalogs"].append(
                catalog_node
            )

        if not schema_name:

            if permission not in catalog_node["permission"]:

                catalog_node["permission"].append(
                    permission
                )

            continue

        # --------------------------------------------------------
        # Schema
        # --------------------------------------------------------

        schema_node = None

        for item in catalog_node["schemas"]:

            if item.get("schema") == schema_name:

                schema_node = item
                break

        if schema_node is None:

            schema_node = {
                "schema": schema_name,
                "permission": [],
                "filters": None,
                "tables": []
            }

            catalog_node["schemas"].append(
                schema_node
            )

        if not table_name:

            if permission not in schema_node["permission"]:

                schema_node["permission"].append(
                    permission
                )

            continue

        # --------------------------------------------------------
        # Table
        # --------------------------------------------------------

        table_node = None

        for item in schema_node["tables"]:

            if item.get("table") == table_name:

                table_node = item
                break

        if table_node is None:

            table_node = {
                "table": table_name,
                "permission": [],
                "filters": None,
                "columns": []
            }

            schema_node["tables"].append(
                table_node
            )

        if not column_name:

            if permission not in table_node["permission"]:

                table_node["permission"].append(
                    permission
                )

            continue

        # --------------------------------------------------------
        # Column
        # --------------------------------------------------------

        column_node = None

        for item in table_node["columns"]:

            if item.get("column") == column_name:

                column_node = item
                break

        if column_node is None:

            column_node = {
                "column": column_name,
                "permission": [],
                "filters": None
            }

            table_node["columns"].append(
                column_node
            )

        if permission not in column_node["permission"]:

            column_node["permission"].append(
                permission
            )

    return result


def get_new_permission_difference(
    candidate_tree,
    cumulative_tree
):
    """
    FIXED permission comparison.

    Compare ONLY:

        candidate_tree

    against:

        cumulative_tree

    The candidate file itself is NEVER searched as an existing policy.

    Therefore:

        candidate:
            UpdateTableColumns

        cumulative:
            no UpdateTableColumns

    produces:

        UpdateTableColumns

    as a new permission.
    """

    candidate_entries = _extract_permission_entries(
        candidate_tree
    )

    cumulative_entries = _extract_permission_entries(
        cumulative_tree
    )

    new_entries = (
        candidate_entries
        -
        cumulative_entries
    )

    return _permission_entries_to_tree(
        new_entries
    )


def _load_cumulative_tree():
    """
    Load the current cumulative permission tree.

    If the cumulative tree does not exist yet, return an empty tree.
    """

    if not os.path.exists(
        TREE_STRUCTURE_PATH
    ):

        return {}

    try:

        with open(
            TREE_STRUCTURE_PATH,
            "r",
            encoding="utf-8"
        ) as f:

            tree = json.load(f)

    except (
        json.JSONDecodeError,
        OSError
    ):

        return {}

    if not isinstance(tree, dict):

        return {}

    return tree


# ============================================================================
# Load structure
# ============================================================================

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


# ============================================================================
# LLM
# ============================================================================

LLAMA_DIR = (
    r"C:\Users\berta\BertaFiles\Project\DataMeshPoliciesLLM"
    r"\LLM\LocalLLMIntelIpex"
    r"\llama-cpp-ipex-llm-2.3.0b20250424-win"
)

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


# ============================================================================
# Pipeline
# ============================================================================

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

    # ========================================================================
    # 1) Explanation
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
            list(
                CHECK_FOR_ACTION.keys()
            ),
            is_local=is_local,
            chat_url=chat_url,
            embedding_url=embedding_url,
            client=client,
            model=model,
            embedding_model=embedding_model
        )

        if (
            not explanation.get(
                "existSecureGroup",
                False
            )
            or
            not explanation.get(
                "pathExistOnDataMeshStructure",
                False
            )
            or
            not explanation.get(
                "actionExist",
                False
            )
        ):

            print(
                "llm_feedback:",
                explanation["llm_feedback"]
            )

            return False, None

        print(
            explanation["text"]
        )

        #print("FULL: ", explanation)

    except Exception as e:

        print(
            "Explanation failed:",
            e
        )

        return False, None

    # ========================================================================
    # 2) Extraction
    # ========================================================================

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

    print(
        "Extracted:"
    )

    print(
        json.dumps(
            entities,
            indent=2,
            ensure_ascii=False
        )
    )

    # ========================================================================
    # 3) Generate Rego
    # ========================================================================

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

    except Exception as e:

        print(
            "Policy generation failed:",
            e
        )

        return False, None

    # ========================================================================
    # 4) Prepare directories
    # ========================================================================

    os.makedirs(
        OUTPUT_REGO_DIR,
        exist_ok=True
    )

    os.makedirs(
        TREE_PERMISSION_DIR,
        exist_ok=True
    )

    os.makedirs(
        OPA_FILE_PATH,
        exist_ok=True
    )

    # ========================================================================
    # 5) Complete Rego
    # ========================================================================

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

    # ========================================================================
    # 6) Generate filename
    # ========================================================================

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

    output_opa_file = os.path.join(
        OPA_FILE_PATH,
        filename
    )

    candidate_tree_file = os.path.join(
        TREE_PERMISSION_DIR,
        "_candidate_tree.json"
    )

    # ========================================================================
    # 7) Write candidate Rego
    # ========================================================================

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            full_policy
        )

    print(
        "\nGenerated candidate policy:",
        output_file
    )

    # ========================================================================
    # 8) Build candidate permission tree
    # ========================================================================

    print(
        "\n[Building candidate permission tree...]"
    )

    try:

        candidate_tree = build_permission_tree(
            opa_file=output_file,
            action_permissions_file=CHECK_FOR_ACTION_PATH,
            security_groups_file=SECURITY_GROUPS_PATH,
            output_file=candidate_tree_file
        )

        print(
            "candidate tree:"
        )

        print(
            json.dumps(
                candidate_tree,
                indent=2,
                ensure_ascii=False
            )
        )

    except Exception as e:

        print(
            "Failed to build permission tree:",
            e
        )

        if os.path.exists(
            output_file
        ):
            os.remove(
                output_file
            )

        return False, None

    # ========================================================================
    # 9) Load ONLY the cumulative tree
    #
    # FIX:
    #
    # Do NOT ask get_permission_difference() to scan TREE_PERMISSION_DIR.
    #
    # That directory contains _candidate_tree.json.
    #
    # We compare the candidate directly with tree_structure.json.
    # ========================================================================

    print(
        "\n[Checking existing permissions...]"
    )

    try:

        cumulative_tree = _load_cumulative_tree()

        difference_tree = get_new_permission_difference(
            candidate_tree,
            cumulative_tree
        )

    except Exception as e:

        print(
            "Failed to compare permission trees:",
            e
        )

        if os.path.exists(
            output_file
        ):
            os.remove(
                output_file
            )

        if os.path.exists(
            candidate_tree_file
        ):
            os.remove(
                candidate_tree_file
            )

        return False, None

    print(
        "\n[Permission difference]"
    )

    print(
        json.dumps(
            difference_tree,
            indent=2,
            ensure_ascii=False
        )
    )

    # ========================================================================
    # 10) No new permissions
    # ========================================================================

    if not difference_tree:

        print(
            "\nNo new permissions found."
        )

        print(
            "Generated policy is already represented "
            "by the cumulative permission tree."
        )

        if os.path.exists(
            output_file
        ):
            os.remove(
                output_file
            )

        if os.path.exists(
            candidate_tree_file
        ):
            os.remove(
                candidate_tree_file
            )

        return True, explanation

    # ========================================================================
    # 11) New permissions found
    # ========================================================================

    print(
        "\nNew permissions detected:"
    )

    print(
        json.dumps(
            difference_tree,
            indent=2,
            ensure_ascii=False
        )
    )

    # ========================================================================
    # 12) Keep generated Rego
    # ========================================================================

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            full_policy
        )

    print(
        "Saved generated policy:",
        output_file
    )

    # ========================================================================
    # 13) Copy SAME policy to OPA
    # ========================================================================

    with open(
        output_opa_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            full_policy
        )

    print(
        "Updated OPA:",
        output_opa_file
    )

    # ========================================================================
    # 14) Rebuild cumulative permission tree
    # ========================================================================

    print(
        "\n[Updating cumulative permission tree...]"
    )

    try:

        complete_tree = build_complete_permission_tree(
            TREE_PERMISSION_DIR,
            TREE_STRUCTURE_PATH,
            OUTPUT_REGO_DIR,
            CHECK_FOR_ACTION_PATH,
            SECURITY_GROUPS_PATH
        )

    except Exception as e:

        print(
            "Failed to rebuild cumulative permission tree:",
            e
        )

        return False, None

    print(
        "\n[Cumulative permission tree]"
    )

    print(
        json.dumps(
            complete_tree,
            indent=2,
            ensure_ascii=False
        )
    )

    print(
        "\nSaved cumulative tree:",
        TREE_STRUCTURE_PATH
    )

    # ========================================================================
    # 15) Remove candidate tree
    # ========================================================================

    if os.path.exists(
        candidate_tree_file
    ):

        os.remove(
            candidate_tree_file
        )

    # ========================================================================
    # 16) Remove duplicated defaults
    # ========================================================================

    remove_duplicate_rego_default(
        OPA_FILE_PATH
    )

    # ========================================================================
    # 17) Restart OPA
    # ========================================================================

    restart_opa()

    return True, explanation


# ============================================================================
# Standalone
# ============================================================================

if __name__ == "__main__":

    print(
        "=" * 50
    )

    print(
        "OPA Policy Generator"
    )

    print(
        "=" * 50
    )

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