import os
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

CHAT_URL = os.getenv( "CHAT_URL", "http://127.0.0.1:8080")
EMBEDDING_URL = os.getenv( "EMBEDDING_URL", "http://127.0.0.1:8081")

MODEL = os.getenv( "OPENAI_MODEL", "gpt-4o-mini")
EMBEDDING_MODEL = os.getenv( "EMBEDDING_MODEL", "text-embedding-3-small")

IS_LOCAL = ( os.getenv("IS_LOCAL", "False").lower() == "true" )

LOCAL_CHAT_MODEL = os.getenv( "LOCAL_CHAT_MODEL" )
LOCAL_EMBEDDING_MODEL = os.getenv( "LOCAL_EMBEDDING_MODEL" )

LLAMA_DIR = os.getenv( "LLAMA_DIR", r"C:\Users\berta\BertaFiles\Project\DataMeshPoliciesLLM" r"\LLM\LocalLLMIntelIpex" r"\llama-cpp-ipex-llm-2.3.0b20250424-win")

CLIENT = OpenAI( api_key=os.getenv("OPENAI_API_KEY") )

# ==========================================================
# PATHS
# ==========================================================

def find_project_dir() -> Path:
    current = Path.cwd().resolve()

    for directory in [current, *current.parents]:
        if directory.name == "DataMeshPoliciesLLM":
            return directory

    raise RuntimeError( "DataMeshPoliciesLLM folder not found." )

DATA_MESH_DIR = find_project_dir()
LLM_DIR = DATA_MESH_DIR / "LLM"

A_GENERATION_PIPELINE_PATH = ( DATA_MESH_DIR / "Pipelines" / "A_GenerationPipeline"  )
B_TEST_GENERATION_PIPELINE_PATH =(DATA_MESH_DIR / "Pipelines" / "B_TestGenerationPipeline" )
C_EVALUATION_TEST_RESULT_PIPELINE_PATH = (DATA_MESH_DIR / "Pipelines" / "C_EvaluationTestResultPipeline")


# --------------------------------------------------------------------------
# STRUCTURE
# --------------------------------------------------------------------------
STRUCTURE_DIR = DATA_MESH_DIR / "Structure"

CHECK_FOR_ACTION_PATH = os.path.join( STRUCTURE_DIR, "checkForAction.json" )
DATA_MESH_STRUCTURE_PATH = os.path.join( STRUCTURE_DIR, "data_mesh.json" )
INPUT_STRUCTURE_PATH = os.path.join( STRUCTURE_DIR, "input.json" )
PERMISSION_DEPTH_PATH = os.path.join( STRUCTURE_DIR, "permission_depth.json" )
SECURITY_GROUPS_PATH = os.path.join( STRUCTURE_DIR, "security_groups.json" )
USER_CREDENTIALS_PATH = os.path.join( STRUCTURE_DIR, "user_credentials.json" )


# -------------------------------------------------------------------------
# OPA file output
# -----------------------------------------------------------------------
DATA_JSON_FILE_RULES = ( DATA_MESH_DIR / "docker-compose" / "opa" / "data.json" )

# --------------------------------------------------------------------------
# OUTPUT GENERATION JSON
# --------------------------------------------------------------------------
OUTPUT_GENERATION_DIR = ( A_GENERATION_PIPELINE_PATH / "output_generation" )

PERMISSION_TREE_MAP = ( OUTPUT_GENERATION_DIR / "single_request_tree" )
PERMISSION_TREE_MAP_PATH = ( PERMISSION_TREE_MAP / "single_request_tree.json" )

CUMULATIVE_TREE_DIR = ( OUTPUT_GENERATION_DIR / "cumulative_tree" )
CUMULATIVE_TREE_PATH = ( CUMULATIVE_TREE_DIR / "cumulative_tree.json" )
CUMULATIVE_TREE_TEMP_PATH = ( CUMULATIVE_TREE_DIR / "cumulative_tree_temp.json" )

GENERATED_RULE_DIR = (OUTPUT_GENERATION_DIR / "generated_rules")
GENERATED_RULE_PATH = (GENERATED_RULE_DIR / "generated_rules.json" )


# ------------------------------------------------------------------------
# OUTPUT TEST GENERATION
# -----------------------------------------------------------------------
OUTPUT_TEST_GENERATION_PATH = (B_TEST_GENERATION_PIPELINE_PATH / "output_test_generation")
OUTPUT_TEST_GENERATION_FILE = (OUTPUT_TEST_GENERATION_PATH / "test_generated.json")


# --------------------------------------------------------------------------
# OUTPUT EVALUATION
# --------------------------------------------------------------------------
OUTPUT_TEST_EVALUATION_PATH = ( C_EVALUATION_TEST_RESULT_PIPELINE_PATH / "output_test_evaluation" )
OUTPUT_TEST_EVALUATION_FILE = (OUTPUT_TEST_EVALUATION_PATH / "test_evaluated.json")
OUTPUT_TEST_EXECUTION_FILE = (OUTPUT_TEST_EVALUATION_PATH / "test_executed.json")


# ------------------------------------------------------------------------------
# EXAMPLE
# -------------------------------------------------------------------------------
DATABASE_DIR=(DATA_MESH_DIR / "LLM" / "LLMPipeline" / "Example"/"Datastore")
DATABASE_EVALUATION_TEST_FILE= (DATABASE_DIR / "EvaluationTest"/ "evaluation_test_examples.json")
DATABASE_REWRITE_RULE_FILE= (DATABASE_DIR / "RewriteRule"/ "rewrite_rule_examples.json")

INDEXED_DIR =os.path.join(DATA_MESH_DIR , "LLM", "LLMPipeline", "Example", "Indexed")
INDEXED_REWRITE_RULE_PATH = os.path.join(INDEXED_DIR , "RewriteRule")
INDEXED_EVALUATION_TEST_PATH = os.path.join(INDEXED_DIR , "EvaluationTest")








#-----------------------------------------------------------
# Benchmarking paths
#-----------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DOCKER_COMPOSE_TRINO_DIR = BASE_DIR / "docker-compose"
DOCKER_COMPOSE_OPA_DIR = BASE_DIR / "StatelessRuleArchitecture" / "docker-opa-stateless"

# ============================================================================
# Configuration
# ============================================================================
SOURCE_FILE = BASE_DIR / "policyReference.rego"
TARGET_DIRECTORIES = [ BASE_DIR / "docker-compose" / "opa", BASE_DIR / "StatelessRuleArchitecture" / "docker-opa-stateless" / "opa"]
