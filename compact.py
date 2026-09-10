import ast
import sys
import shutil
from pathlib import Path


MAX_LINE_LENGTH = 100


def compact_python(source: str) -> str:
    """
    Compact Python source code by removing excessive blank lines
    and collapsing simple multiline constructs when possible.

    The Python AST is used to identify safe structural boundaries.
    """

    lines = source.splitlines()

    # ---------------------------------------------------------
    # Remove excessive blank lines
    # ---------------------------------------------------------

    cleaned = []
    previous_blank = False

    for line in lines:
        stripped = line.strip()

        if not stripped:
            if not previous_blank:
                cleaned.append("")
            previous_blank = True
            continue

        cleaned.append(line.rstrip())
        previous_blank = False

    # ---------------------------------------------------------
    # Remove blank lines immediately inside blocks
    # ---------------------------------------------------------

    result = []

    for i, line in enumerate(cleaned):
        if not line.strip():
            prev = cleaned[i - 1].strip() if i > 0 else ""
            nxt = cleaned[i + 1].strip() if i + 1 < len(cleaned) else ""

            if prev.endswith(":") or nxt.startswith(("def ", "class ", "@")):
                continue

        result.append(line)

    source = "\n".join(result).rstrip() + "\n"

    # Validate that we did not damage the Python source.
    ast.parse(source)

    return source


def format_file(path: Path, backup: bool = True):
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if path.suffix != ".py":
        raise ValueError(f"Expected a Python file: {path}")

    original = path.read_text(encoding="utf-8")

    # Validate original code first.
    ast.parse(original)

    if backup:
        backup_path = path.with_suffix(path.suffix + ".bak")
        shutil.copy2(path, backup_path)
        print(f"Backup: {backup_path}")

    formatted = compact_python(original)

    path.write_text(formatted, encoding="utf-8")

    print(f"Formatted: {path}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python compact.py <file.py>")
        print()
        print("Example:")
        print("  python compact.py TreePermission/tree_builder.py")
        sys.exit(1)

    path = Path(sys.argv[1])

    try:
        format_file(path)
    except SyntaxError as e:
        print(f"Python syntax error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()