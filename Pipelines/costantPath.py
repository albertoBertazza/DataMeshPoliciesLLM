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
DOCKER_COMPOSE_PATH= os.path.join( DATA_MESH_DIR, "docker-compose" )
LLM_DIR = DATA_MESH_DIR / "LLM"

A_GENERATION_PIPELINE_PATH = ( DATA_MESH_DIR / "Pipelines" / "A_GenerationPipeline"  )
B_TEST_GENERATION_PIPELINE_PATH =(DATA_MESH_DIR / "Pipelines" / "B_TestAndGenerationPipeline" )

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
ACTION_SQL_MAPPING_PATH = os.path.join( STRUCTURE_DIR, "action_sql_mapping.json" )

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

REWRITTEN_RULE_DIR = (OUTPUT_GENERATION_DIR / "rewritten_rule")
REWRITTEN_RULE_PATH = (REWRITTEN_RULE_DIR / "rewritten_rule.json" )

# ------------------------------------------------------------------------
# OUTPUT TEST GENERATION
# -----------------------------------------------------------------------
OUTPUT_TEST_GENERATION_PATH = (B_TEST_GENERATION_PIPELINE_PATH / "output_test_generation")
OUTPUT_TEST_GENERATION_FILE = (OUTPUT_TEST_GENERATION_PATH / "test_generated.json")

# --------------------------------------------------------------------------
# OUTPUT EVALUATION
# --------------------------------------------------------------------------
OUTPUT_TEST_EVALUATION_PATH = ( B_TEST_GENERATION_PIPELINE_PATH / "output_test_evaluation" )
OUTPUT_TEST_EVALUATION_FILE = (OUTPUT_TEST_EVALUATION_PATH / "test_evaluated.json")
OUTPUT_TEST_EXECUTION_FILE = (OUTPUT_TEST_EVALUATION_PATH / "test_executed.json")

# ------------------------------------------------------------------------------
# EXAMPLE
# -------------------------------------------------------------------------------
DATABASE_DIR=(DATA_MESH_DIR / "LLM" / "LLMPipeline" / "Example"/"Datastore")
DATABASE_REWRITE_RULE_FILE= (DATABASE_DIR / "RewriteRule"/ "rewrite_rule_examples.json")

INDEXED_DIR =os.path.join(DATA_MESH_DIR , "LLM", "LLMPipeline", "Example", "Indexed")
INDEXED_REWRITE_RULE_PATH = os.path.join(INDEXED_DIR , "RewriteRule")



EXAMPLE_RULES =[
    "hr_manager can add column in hr.people",
    "hr_manager can create materialized view on hr.people",
    "hr_manager can create schema inside iceberg",
    "hr_manager can create table inside hr schema",
    "hr_manager can create view on finance.employee_finance",
    "hr_manager can select from table in sales schema",
    "hr_manager can delete from support.support_tickets",
    "hr_manager can drop column inside support.support_tickets",
    "hr_manager can drop table support.support_tickets",
    "hr_manager can drop schema support",
    "hr_manager can insert a new entity inside schema hr",
    "hr_manager can rename a column inside procurement",
    "hr_manager can rename table inside procurement schema",
    "hr_manager can add comment to column in schema sales",
    "hr_manager can add comment to table in schema sales",
    "hr manager can execute show columns inside schema sales", # WARNING denied to required internal  SelectFromColumns Resource: iceberg.information_schema
    "hr manager can ask to show the create schema function in iceberg",
    "hr manager can ask to show the create table function in iceberg.sales",
    "hr manager can see the list of schemas inside iceberg",
    "hr manager can see the list of table inside iceberg.sales",
    "hr manager can update an entity inside the iceberg.sales",

    "auditor is not allowed to select any table inside the iceberg catalog", # DENY PERMISSION
    "auditor is allowed to select any table inside schema sales", # ALLOW PERMISSION, but denied at catalog level

    "hr manager can truncate table inside iceberg.sales",

    "hr manager can comment view inside sales schema", # OPERATION ON VIEW AND MATERIALIZED VIEW
    "hr manager can rename view inside iceberg.sales",
    "hr manager can rename materialized view inside iceberg.sales",
    "hr manager can refresh materialized view inside inventory schema",
    "hr manager can drop materialized view inside inventory schema",
    "hr manager can drop view inside inventory schema",
]



# =================================================================
# STATELESS STATEFUL ANALYSIS
# =================================================================

ANALYSIS_DIR= os.path.join(DATA_MESH_DIR ,  "Analysis")
ANALYSIS_OUTPUT = os.path.join(ANALYSIS_DIR , "output")

OUTPUT_STATEFUL_PATH = os.path.join(ANALYSIS_OUTPUT , "output_stateful.json")
OUTPUT_STATELESS_PATH = os.path.join(ANALYSIS_OUTPUT , "output_stateless.json")
OUTPUT_BENCHMARK_DIR = os.path.join(ANALYSIS_OUTPUT , "benchmark")

STATEFUL_OPA_DOCKER_DIR = os.path.join(ANALYSIS_DIR , "docker-opa-stateful")
STATELESS_OPA_DOCKER_DIR = os.path.join(ANALYSIS_DIR , "docker-opa-stateless")

OPA_STATEFUL_DIR= os.path.join(STATEFUL_OPA_DOCKER_DIR , "opa")
OPA_STATELESS_DIR = os.path.join(STATELESS_OPA_DOCKER_DIR , "opa")

DATA_STATEFUL_PATH = os.path.join(OPA_STATEFUL_DIR , "data.json")
DATA_STATELESS_PATH = os.path.join(OPA_STATELESS_DIR , "data.json")

DATA_JSON_EXAMPLE_ANALYSIS = os.path.join(ANALYSIS_DIR , "data.json")


STATEFUL_PORT = 8182
STATELESS_PORT = 8183

OPA_URL_STATELESS = f"http://localhost:{STATELESS_PORT}/v1/data/trino/authz/allow"
OPA_URL_STATEFUL = f"http://localhost:{STATEFUL_PORT}/v1/data/trino/authz/allow"