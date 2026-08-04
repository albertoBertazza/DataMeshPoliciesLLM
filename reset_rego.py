from pathlib import Path
import shutil

def delete_files_generated():
    # Delete all .rego files inside docker-compose/opa
    opa_dir = Path("docker-compose/opa")
    if opa_dir.exists():
        for rego_file in opa_dir.glob("*.rego"):
            rego_file.unlink()
            print(f"Deleted: {rego_file}")

    rego_policies=Path("LLM/LLMPipeline/RegoPolicyCreation/output/rego_policies")
    if rego_policies.exists():
        for rego_file in rego_policies.glob("*.rego"):
            rego_file.unlink()
            print(f"Deleted: {rego_file}")

    eval=Path("LLM/LLMPipeline/Evaluation/Output")
    if eval.exists():
        for rego_file in eval.glob("*.json"):
            rego_file.unlink()
            print(f"Deleted: {rego_file}")

    test_interaction=Path("LLM/LLMPipeline/TrinoTestInteraction/output/generated_tests")
    if test_interaction.exists():
        for rego_file in test_interaction.glob("*.json"):
            rego_file.unlink()
            print(f"Deleted: {rego_file}")

    test = Path("Tester/output")
    if test.exists():
        for rego_file in test.glob("*.json"):
            rego_file.unlink()
            print(f"Deleted: {rego_file}")

    tree = Path("LLM/LLMPipeline/RegoPolicyCreation/output/tree_permission")
    if tree.exists():
        for rego_file in tree.glob("*.json"):
            rego_file.unlink()
            print(f"Deleted: {rego_file}")

    tree_out=Path("TreePermission/output")
    if tree_out.exists():
        for rego_file in tree_out.glob("*.json"):
            rego_file.unlink()
            print(f"Deleted: {rego_file}")


if __name__ == "__main__":
    delete_files_generated()

    # Assuming this script is in the project root
    project_root = Path(__file__).resolve().parent

    source = project_root / "policyReference.rego"
    destination = project_root / "docker-compose" / "opa" / "policy.rego"

    shutil.copyfile(source, destination)

    print(f"Copied {source} -> {destination}")