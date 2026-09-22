import json
from pathlib import Path
from typing import Any


def load_json(path):

    with open(path, "r",encoding="utf-8") as f:
        return json.load(f)

def load_json_file(path: Path) -> Any:

    if not path.exists():
        raise FileNotFoundError( f"File not found:\n{path}" )

    with path.open( "r", encoding="utf-8") as file:
        return json.load(file)

def save_json_file(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def load_text(path):
    with open(path, "r", encoding="utf-8" ) as f:
        return f.read()