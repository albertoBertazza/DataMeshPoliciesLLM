from pathlib import Path
import shutil

from Pipelines.costantPath import CUMULATIVE_TREE_PATH


def delete_files_generated():
    # # Delete all .rego files inside docker-compose/opa
    # opa_dir = Path("docker-compose/opa")
    # if opa_dir.exists():
    #     for rego_file in opa_dir.glob("data.json"):
    #         rego_file.unlink()
    #         print(f"Deleted: {rego_file}")

    # rego_policies=Path("LLM/LLMPipeline/RegoPolicyCreation/output/rego_policies")
    # if rego_policies.exists():
    #     for rego_file in rego_policies.glob("*.rego"):
    #         rego_file.unlink()
    #         print(f"Deleted: {rego_file}")



    cumulative_tree=CUMULATIVE_TREE_PATH
    cumulative_tree.exists()
    cumulative_tree.unlink()
    print(f"Deleted: {cumulative_tree}")


if __name__ == "__main__":
    delete_files_generated()

    # Assuming this script is in the project root
    project_root = Path(__file__).resolve().parent

    # source = project_root / "policyReference.rego"
    # destination = project_root / "docker-compose" / "opa" / "policy.rego"

    # shutil.copyfile(source, destination)
    #
    # print(f"Copied {source} -> {destination}")