import json
import os
import shutil
import traceback
from typing import Any, Dict
from openai import OpenAI
from Function.jsonHelper import load_json
from LLM.Interface.activate_local_llm import activate_llm
from LLM.LLMPipeline.IndexCreation.Rewrite.gen_index_rewrite import gen_index_rewrite
from LLM.LLMPipeline.IndexCreation.index_creator import ( reload_indexes)
from Pipelines.A_GenerationPipeline.B_Extraction.extraction import (build_intermediate_representation)
from Pipelines.A_GenerationPipeline.A_Rewrite.LLM_rule_rewrite import (llm_explain)
from Pipelines.A_GenerationPipeline.C_PermissionTree.permission_tree_writer import ( PermissionTreeWriter)
from Pipelines.A_GenerationPipeline.C_PermissionTree.permission_tree_merger import ( PermissionTreeMerger)
from Pipelines.A_GenerationPipeline.E_Compiler.permission_compiler import ( PermissionCompiler)
from Pipelines.A_GenerationPipeline.D_PolicyWriter.policy_writer import ( PolicyWriter)
from Pipelines.costantPath import LLAMA_DIR, IS_LOCAL, CHAT_URL, LOCAL_CHAT_MODEL, EMBEDDING_URL, LOCAL_EMBEDDING_MODEL, \
    EMBEDDING_MODEL, MODEL, PERMISSION_TREE_MAP_PATH, \
    SECURITY_GROUPS_PATH, DATA_MESH_STRUCTURE_PATH, PERMISSION_DEPTH_PATH, CHECK_FOR_ACTION_PATH, DATA_MESH_DIR, \
        CUMULATIVE_TREE_TEMP_PATH, GENERATED_RULE_PATH, DATA_JSON_FILE_RULES, DATABASE_REWRITE_RULE_FILE, INDEXED_REWRITE_RULE_PATH, CUMULATIVE_TREE_PATH

# ============================================================================
# Permission-tree helpers
# ============================================================================

def load_existing_permission_tree() -> Dict[str, Any]:
    """
    Load the accumulated intermediate permission tree.

    If this is the first rule, there is no existing tree yet.
    """
    if not CUMULATIVE_TREE_PATH.exists():
        print("\nWARN: no cumulative tree saved yet\n")
        return {}
    print( "\n[Loading existing permission tree]" )
    tree = PermissionTreeWriter.load( str(CUMULATIVE_TREE_PATH) )
    if not isinstance(tree, dict):
        raise ValueError( "tree_permission must contain a JSON object." )
    return tree

def save_final_cumulative_tree():
    if not CUMULATIVE_TREE_TEMP_PATH.exists():
        return {}
    CUMULATIVE_TREE_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile( CUMULATIVE_TREE_TEMP_PATH, CUMULATIVE_TREE_PATH )
    print("Saved final cumulative tree: ", CUMULATIVE_TREE_PATH)
    return {}

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
    print( "\n[ 3.1 Merging permission trees]" )
    merger = PermissionTreeMerger()
    merged_tree = merger.merge( existing_tree, extracted_tree)
    PermissionTreeWriter.write( merged_tree, str(CUMULATIVE_TREE_TEMP_PATH))
    print( "Saved merged tree:", CUMULATIVE_TREE_TEMP_PATH)
    return merged_tree

# ============================================================================
# Canonical OPA compilation
# ============================================================================

def compile_canonical_policy(merged_tree: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compile the merged intermediate permission tree into
    the canonical OPA JSON structure.
    """

    print("\n[ 5. Compiling canonical OPA policy]")
    compiler = PermissionCompiler(data_mesh_file=str(DATA_MESH_STRUCTURE_PATH),security_groups_file=str(SECURITY_GROUPS_PATH),permission_depth_file=str(PERMISSION_DEPTH_PATH), )
    canonical_policy = compiler.compile(merged_tree )
    return canonical_policy

def save_canonical_policy( canonical_policy: Dict[str, Any]) -> None:
    """
    Write the final canonical policy to both destinations:

        output/rego_policies/data.json
        docker-compose/opa/data.json
    """

    print( "\n[ 4. Writing final canonical OPA policy]" )
    writer = PolicyWriter()
    writer.write_final_policy( policy=canonical_policy, rego_output_file=str( GENERATED_RULE_PATH ), opa_data_file=str( DATA_JSON_FILE_RULES ))
    print( "Saved:", GENERATED_RULE_PATH)
    print( "Saved:", DATA_JSON_FILE_RULES)

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
    print( "\n[ Merged permission tree]" )
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
    save_final_cumulative_tree()
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
    chat_url: str = '',
    embedding_url: str = '',
    client=None,
    model: str = '',
    embedding_model: str = '',
    skip_user_check: bool = False
):
    # ========================================================================
    # 1. Explanation
    # ========================================================================

    print( "\n[ 1. LLM rule rewrite]" )

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
        return False

    if not explanation.get( "existSecureGroup", False):
        print( "Invalid security group." )
        print( "llm_feedback:", explanation.get( "llm_feedback", ""))
        return False

    if not explanation.get( "pathExistOnDataMeshStructure", False):
        print( "Resource path does not exist." )
        print( "llm_feedback:", explanation.get( "llm_feedback", ""))
        return False

    if not explanation.get( "actionExist", False):
        print( "Action does not exist." )
        print( "llm_feedback:", explanation.get( "llm_feedback", ""))
        return False

    print( json.dumps( explanation, indent=2, ensure_ascii=False) )

    if not skip_user_check:
        print("#" + "=" * 60)
        print("# Do you mean? ")
        print("#\t"+explanation.get( "text", ""))
        print("#" + "=" * 60)

        answer = ""
        while answer != "y" and answer != "n":
            answer = input("Do you wanna accept this interpretation? [y/n]: ").strip().lower()

        if answer == "n":
            return False

    # ========================================================================
    # 2. Extraction
    # ========================================================================

    print( "\n[ 2. Extracting entities...]" )

    try:
        permission_depth = load_json( PERMISSION_DEPTH_PATH )["permission_depth"]
        entities = build_intermediate_representation( explanation, check_for_action, permission_depth=permission_depth)
    except ValueError as error:
        print( "Extraction failed:", error)
        return False
    except Exception as error:
        print( "Extraction failed:", error)
        return False

    if entities is None:
        print( "Extraction returned no entities." )

        return False
    print( "\n[ Extracted permission tree]" )
    print( json.dumps( entities, indent=2, ensure_ascii=False) )
    # ========================================================================
    # 3. Permission-tree → merge → compiler → OPA
    # ========================================================================

    try:
        build_permission_policy( entities )
    except Exception as error:
        print( "Permission-policy pipeline failed:", error)
        traceback.print_exc()
        return False

    return True

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
    print( f"Project root:          {DATA_MESH_DIR}" )
    print( f"Data mesh:             {DATA_MESH_STRUCTURE_PATH}" )
    print( f"Security groups:       {SECURITY_GROUPS_PATH}" )
    print( f"Check actions:         {CHECK_FOR_ACTION_PATH}" )
    print( f"Latest extraction:     {PERMISSION_TREE_MAP_PATH}" )
    print( f"Merged tree:           {CUMULATIVE_TREE_TEMP_PATH}" )
    print( f"Final cumulative tree: {CUMULATIVE_TREE_PATH}")
    print( f"Final OPA policy:      {GENERATED_RULE_PATH}" )
    print( f"OPA data.json:         {DATA_JSON_FILE_RULES}" )

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
    index_rewrite_rule = reload_indexes( IS_LOCAL, embedding_url=EMBEDDING_URL, client=client, embedding_model=EMBEDDING_MODEL, database_path=DATABASE_REWRITE_RULE_FILE,index_path=INDEXED_REWRITE_RULE_PATH,filename="rewrite_rule_example", gen_index_function=gen_index_rewrite)

    # ========================================================================
    # Interactive loop
    # ========================================================================

    while True:
        rule = input( "\nRule: " ).strip()
        if rule.lower() in ( "exit", "quit"):
            break
        if not rule:
            continue

        success = process_rule(
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
            skip_user_check=False
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
