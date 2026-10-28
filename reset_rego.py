from pathlib import Path
from Pipelines.costantPath import CUMULATIVE_TREE_PATH


def delete_files_generated():
    cumulative_tree=CUMULATIVE_TREE_PATH
    if cumulative_tree.exists():
        cumulative_tree.unlink()
        print(f"Deleted: {cumulative_tree}")
    else:
        print(f"Not find any: {CUMULATIVE_TREE_PATH}")




if __name__ == "__main__":
    delete_files_generated()
    # Assuming this script is in the project root
    project_root = Path(__file__).resolve().parent
