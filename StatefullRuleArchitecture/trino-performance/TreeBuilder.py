import os
from dotenv import load_dotenv
from openai import OpenAI

from TreePermission.tree_builder import build_permission_tree_from_directory

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
from pathlib import Path

DATA_MESH_DIR = Path(
    __file__
).resolve().parent.parent.parent

print(DATA_MESH_DIR)

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


DOCKER_COMPOSE_PATH = os.path.join(
    DATA_MESH_DIR,
    "docker-compose"
)

OPA_FILE_PATH = os.path.join(
    DOCKER_COMPOSE_PATH,
    "opa"
)

OUTPUT_PATH = os.path.join(os.path.join(os.path.join(os.path.join(DATA_MESH_DIR,"StatefullRuleArchitecture" ), "trino-performance"), "tree_permission"), "tree.json")

build_permission_tree_from_directory( OPA_FILE_PATH,CHECK_FOR_ACTION_PATH,SECURITY_GROUPS_PATH,OUTPUT_PATH)
