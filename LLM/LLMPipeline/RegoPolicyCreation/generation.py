import json
import os
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv
from openai import OpenAI

from Function.LoadJson import load_json

from LLM.Interface.activate_local_llm import activate_llm

from LLM.LLMPipeline.RegoPolicyCreation.IndexCreation.index_creator import ( reload_indexes)

from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.Extraction.extraction import ( build_intermediate_representation)

from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.Rewrite.nlp_rule_rewrite import ( llm_explain)

from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.PermissionTree.permission_tree_writer import ( PermissionTreeWriter)

from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.PermissionTree.permission_tree_merger import ( PermissionTreeMerger)

from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.Compiler.permission_compiler import ( PermissionCompiler)

from LLM.LLMPipeline.RegoPolicyCreation.Pipeline.PolicyWriter.policy_writer import ( PolicyWriter)

# ============================================================================
# Configuration
# ============================================================================

load_dotenv()

CHAT_URL = os.getenv( "CHAT_URL", "http://127.0.0.1:8080")

EMBEDDING_URL = os.getenv( "EMBEDDING_URL", "http://127.0.0.1:8081")

MODEL = os.getenv( "OPENAI_MODEL", "gpt-4o-mini")

EMBEDDING_MODEL = os.getenv( "EMBEDDING_MODEL", "text-embedding-3-small")

IS_LOCAL = ( os.getenv("IS_LOCAL", "False").lower() == "true" )

LOCAL_CHAT_MODEL = os.getenv( "LOCAL_CHAT_MODEL" )

LOCAL_EMBEDDING_MODEL = os.getenv( "LOCAL_EMBEDDING_MODEL" )

LLAMA_DIR = os.getenv( "LLAMA_DIR", r"C:\Users\berta\BertaFiles\Project\DataMeshPoliciesLLM" r"\LLM\LocalLLMIntelIpex" r"\llama-cpp-ipex-llm-2.3.0b20250424-win")

# ============================================================================
# Project paths
# ============================================================================

def find_project_dir() -> Path:
    current = Path.cwd().resolve()

    for directory in [current, *current.parents]:
        if directory.name == "DataMeshPoliciesLLM":
            return directory

    raise RuntimeError( "DataMeshPoliciesLLM folder not found." )

DATA_MESH_DIR = find_project_dir()

LLM_DIR = DATA_MESH_DIR / "LLM"

STRUCTURE_DIR = LLM_DIR / "Structure"

REGO_POLICY_CREATION_DIR = ( LLM_DIR / "LLMPipeline" / "RegoPolicyCreation" )

COMPILER_DIR = ( REGO_POLICY_CREATION_DIR / "Pipeline" / "Compiler" )

OUTPUT_DIR = ( REGO_POLICY_CREATION_DIR / "output" )

# --------------------------------------------------------------------------
# Input structures
# --------------------------------------------------------------------------

CHECK_FOR_ACTION_PATH = ( STRUCTURE_DIR / "checkForAction.json" )

SECURITY_GROUPS_PATH = ( STRUCTURE_DIR / "security_groups.json" )

DATA_MESH_STRUCTURE_PATH = ( STRUCTURE_DIR / "data_mesh.json" )

INPUT_STRUCTURE_PATH = ( STRUCTURE_DIR / "input.json" )

PERMISSION_DEPTH_PATH = ( STRUCTURE_DIR / "permission_depth.json" )

# --------------------------------------------------------------------------
# Permission-tree pipeline
# --------------------------------------------------------------------------

PERMISSION_TREE_MAP = ( OUTPUT_DIR / "last_requested_rule_tree_permission" )

PERMISSION_TREE_MAP_PATH = ( PERMISSION_TREE_MAP / "permission_tree_last_request.json" )

TREE_PERMISSION_DIR = ( OUTPUT_DIR / "tree_permission" )

TREE_PERMISSION_PATH = ( TREE_PERMISSION_DIR / "permission_tree.json" )

# --------------------------------------------------------------------------
# Final canonical OPA policy
# --------------------------------------------------------------------------

REGO_POLICY_OUTPUT_DIR = ( OUTPUT_DIR / "rego_policies" )

REGO_POLICY_OUTPUT_PATH = ( REGO_POLICY_OUTPUT_DIR / "data.json" )

OPA_DATA_PATH = ( DATA_MESH_DIR / "docker-compose" / "opa" / "data.json" )

# ============================================================================
# JSON helpers
# ============================================================================

def load_json_file(path: Path) -> Any:

    if not path.exists():
        raise FileNotFoundError( f"File not found:\n{path}" )

    with path.open( "r", encoding="utf-8") as file:
        return json.load(file)

def save_json_file( data: Any, path: Path) -> None:

    path.parent.mkdir( parents=True, exist_ok=True)

    with path.open( "w", encoding="utf-8") as file:

        json.dump( data, file, indent=2, ensure_ascii=False)

# ============================================================================
# Permission-tree helpers
# ============================================================================

def load_existing_permission_tree() -> Dict[str, Any]:
    """
    Load the accumulated intermediate permission tree.

    If this is the first rule, there is no existing tree yet.
    """

    if not TREE_PERMISSION_PATH.exists():
        return {}

    print( "\n[Loading existing permission tree]" )

    tree = PermissionTreeWriter.load( str(TREE_PERMISSION_PATH) )

    if not isinstance(tree, dict):
        raise ValueError( "tree_permission must contain a JSON object." )

    return tree

def save_extracted_permission_tree( extracted_tree: Dict[str, Any]) -> None:
    """
    Save only the latest extraction.

    This file is NOT the accumulated tree.
    It represents the result of the current extraction.
    """

    print( "\n[Saving extracted permission tree]" )

    PermissionTreeWriter.write( extracted_tree, str(PERMISSION_TREE_MAP_PATH))

    print( "Saved:", PERMISSION_TREE_MAP_PATH)

def merge_permission_tree( existing_tree: Dict[str, Any], extracted_tree: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge the newly extracted permission tree into the
    accumulated permission tree.
    """

    print( "\n[Merging permission trees]" )

    merger = PermissionTreeMerger()

    merged_tree = merger.merge( existing_tree, extracted_tree)

    PermissionTreeWriter.write( merged_tree, str(TREE_PERMISSION_PATH))

    print( "Saved merged tree:", TREE_PERMISSION_PATH)

    return merged_tree

# ============================================================================
# Canonical OPA compilation
# ============================================================================

def compile_canonical_policy(merged_tree: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compile the merged intermediate permission tree into
    the canonical OPA JSON structure.
    """

    print("\n[Compiling canonical OPA policy]")

    compiler = PermissionCompiler(data_mesh_file=str(DATA_MESH_STRUCTURE_PATH),security_groups_file=str(SECURITY_GROUPS_PATH),permission_depth_file=str(PERMISSION_DEPTH_PATH), )

    canonical_policy = compiler.compile(merged_tree )

    return canonical_policy

def save_canonical_policy( canonical_policy: Dict[str, Any]) -> None:
    """
    Write the final canonical policy to both destinations:

        output/rego_policies/data.json
        docker-compose/opa/data.json
    """

    print( "\n[Writing final canonical OPA policy]" )

    writer = PolicyWriter()

    writer.write_final_policy( policy=canonical_policy, rego_output_file=str( REGO_POLICY_OUTPUT_PATH ), opa_data_file=str( OPA_DATA_PATH ))

    print( "Saved:", REGO_POLICY_OUTPUT_PATH)

    print( "Saved:", OPA_DATA_PATH)

# ============================================================================
# Complete permission-policy bridge
# ============================================================================

def build_permission_policy( extracted_tree: Dict[str, Any]) -> Dict[str, Any]:
    """
    Complete bridge after extraction:

        extracted tree
            ↓
        latest extraction file
            ↓
        load previous tree
            ↓
        merge
            ↓
        save tree_permission
            ↓
        compile
            ↓
        save canonical OPA policy
    """

    # ------------------------------------------------------------------------
    # 1. Save latest extraction
    # ------------------------------------------------------------------------

    save_extracted_permission_tree( extracted_tree )

    # ------------------------------------------------------------------------
    # 2. Load accumulated tree
    # ------------------------------------------------------------------------

    existing_tree = ( load_existing_permission_tree() )

    # ------------------------------------------------------------------------
    # 3. Merge
    # ------------------------------------------------------------------------

    merged_tree = merge_permission_tree( existing_tree, extracted_tree)

    print( "\n[Merged permission tree]" )

    print( json.dumps( merged_tree, indent=2, ensure_ascii=False) )

    # ------------------------------------------------------------------------
    # 4. Compile
    # ------------------------------------------------------------------------

    canonical_policy = compile_canonical_policy( merged_tree )

    print( "\n[Canonical OPA policy]" )

    print( json.dumps( canonical_policy, indent=2, ensure_ascii=False) )

    # ------------------------------------------------------------------------
    # 5. Write final policy
    # ------------------------------------------------------------------------

    save_canonical_policy( canonical_policy )

    return canonical_policy

# ============================================================================
# Rule processing
# ============================================================================

def process_rule(
    rule_passed: str,
    index_rewrite_rule,
    check_for_action: Dict[str, Any],
    data_mesh: Dict[str, Any],
    security_groups: Any,
    is_local: bool = False,
    chat_url: str = None,
    embedding_url: str = None,
    client=None,
    model: str = None,
    embedding_model: str = None,
):
    # ========================================================================
    # 1. Explanation
    # ========================================================================

    print( "\n[Interpretation]" )

    try:

        explanation = llm_explain(
            rule_passed,
            index_rewrite_rule,
            data_mesh,
            security_groups,
            list( check_for_action.keys() ),
            is_local=is_local,
            chat_url=chat_url,
            embedding_url=embedding_url,
            client=client,
            model=model,
            embedding_model=embedding_model,
        )

    except Exception as error:

        print( "Explanation failed:", error)

        return False, None

    if not explanation.get( "existSecureGroup", False):

        print( "Invalid security group." )

        print( "llm_feedback:", explanation.get( "llm_feedback", ""))

        return False, None

    if not explanation.get( "pathExistOnDataMeshStructure", False):

        print( "Resource path does not exist." )

        print( "llm_feedback:", explanation.get( "llm_feedback", ""))

        return False, None

    if not explanation.get( "actionExist", False):

        print( "Action does not exist." )

        print( "llm_feedback:", explanation.get( "llm_feedback", ""))

        return False, None

    print( json.dumps( explanation, indent=2, ensure_ascii=False) )

    # ========================================================================
    # 2. Extraction
    # ========================================================================

    print( "\n[Extracting entities...]" )

    try:

        permission_depth = load_json( PERMISSION_DEPTH_PATH )["permission_depth"]

        entities = build_intermediate_representation( explanation, check_for_action, permission_depth=permission_depth)

    except Exception as error:

        print( "Extraction failed:", error)

        return False, None

    if entities is None:

        print( "Extraction returned no entities." )

        return False, None

    print( "\n[Extracted permission tree]" )

    print( json.dumps( entities, indent=2, ensure_ascii=False) )

    # ========================================================================
    # 3. Permission-tree → merge → compiler → OPA
    # ========================================================================

    try:

        canonical_policy = ( build_permission_policy( entities ) )

    except Exception as error:

        print( "Permission-policy pipeline failed:", error)

        return False, None

    return True, canonical_policy

# ============================================================================
# LLM initialization
# ============================================================================

def initialize_llm():

    client = OpenAI( api_key=os.getenv( "OPENAI_API_KEY" ) )

    activate_llm( LLAMA_DIR, IS_LOCAL, CHAT_URL, LOCAL_CHAT_MODEL, "8080")

    activate_llm( LLAMA_DIR, IS_LOCAL, EMBEDDING_URL, LOCAL_EMBEDDING_MODEL, "8081", other_params=" --embedding")

    return client

# ============================================================================
# Main
# ============================================================================

def main():

    print( "=" * 70 )

    print( "OPA POLICY GENERATOR" )

    print( "=" * 70 )

    print( f"Project root:       {DATA_MESH_DIR}" )

    print( f"Data mesh:          {DATA_MESH_STRUCTURE_PATH}" )

    print( f"Security groups:    {SECURITY_GROUPS_PATH}" )

    print( f"Check actions:      {CHECK_FOR_ACTION_PATH}" )

    print( f"Latest extraction:  {PERMISSION_TREE_MAP_PATH}" )

    print( f"Merged tree:        {TREE_PERMISSION_PATH}" )

    print( f"Final OPA policy:   {REGO_POLICY_OUTPUT_PATH}" )

    print( f"OPA data.json:      {OPA_DATA_PATH}" )

    # ========================================================================
    # Load structures
    # ========================================================================

    check_for_action = load_json( CHECK_FOR_ACTION_PATH )

    security_groups = load_json( SECURITY_GROUPS_PATH )

    data_mesh = load_json( DATA_MESH_STRUCTURE_PATH )

    # ========================================================================
    # Initialize LLM
    # ========================================================================

    client = initialize_llm()

    # ========================================================================
    # Load indexes
    # ========================================================================

    ( index_rewrite_rule, _index_build_rego) = reload_indexes( IS_LOCAL, embedding_url=EMBEDDING_URL, client=client, embedding_model=EMBEDDING_MODEL)

    # ========================================================================
    # Interactive loop
    # ========================================================================

    while True:

        rule = input( "\nRule: " ).strip()

        if rule.lower() in ( "exit", "quit"):
            break

        if not rule:
            continue

        success, result = process_rule(
            rule_passed=rule,
            index_rewrite_rule=index_rewrite_rule,
            check_for_action=check_for_action,
            data_mesh=data_mesh,
            security_groups=security_groups,
            is_local=IS_LOCAL,
            chat_url=CHAT_URL,
            embedding_url=EMBEDDING_URL,
            client=client,
            model=MODEL,
            embedding_model=EMBEDDING_MODEL,
        )

        if success:

            print( "\n" + "=" * 70 )

            print( "POLICY PIPELINE COMPLETED" )

            print( "=" * 70 )

        else:

            print( "\nPolicy pipeline failed." )

# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    main()
