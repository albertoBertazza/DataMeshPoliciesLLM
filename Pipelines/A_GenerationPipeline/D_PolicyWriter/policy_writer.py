import json
from pathlib import Path
from typing import Any, Dict

class PolicyWriter:

    @staticmethod
    def write( policy: Dict[str, Any], output_file: str) -> None:
        path = Path(output_file)
        path.parent.mkdir( parents=True, exist_ok=True)
        with open( path, "w", encoding="utf-8") as file:
            json.dump( policy, file, indent=2, ensure_ascii=False)
            file.write("\n")

    @staticmethod
    def load( input_file: str) -> Dict[str, Any]:
        path = Path(input_file)
        if not path.exists():
            return { "version": "2.0-opa", "rules": {}}
        with open( path, "r", encoding="utf-8") as file:
            data = json.load(file)
        if not isinstance(data, dict):
            raise ValueError( "OPA policy must be a JSON object" )
        return data

    @classmethod
    def write_final_policy( cls, policy: Dict[str, Any], rego_output_file: str, opa_data_file: str) -> None:
        # ------------------------------------------------------------
        # Final generated policy
        # ------------------------------------------------------------
        cls.write( policy, rego_output_file)
        # ------------------------------------------------------------
        # Policy consumed by OPA
        # ------------------------------------------------------------
        cls.write( policy, opa_data_file)
