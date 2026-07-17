from pathlib import Path
import shutil

# Assuming this script is in the project root
project_root = Path(__file__).resolve().parent

source = project_root / "policyReference.rego"
destination = project_root / "docker-compose" / "opa" / "policy.rego"

shutil.copyfile(source, destination)

print(f"Copied {source} -> {destination}")