import ast
import io
import sys
import tokenize
from pathlib import Path

MAX_LINE_LENGTH = 250

def _indent(line):
    return line[:len(line) - len(line.lstrip())]

def _has_comment(lines):
    return any( line.strip().startswith("#") for line in lines )

def _is_multiline_string(source, line_number):
    try:
        tokens = tokenize.generate_tokens( io.StringIO(source).readline )

        for token in tokens:
            if token.type == tokenize.STRING:
                if token.start[0] < line_number <= token.end[0]:
                    return True

    except tokenize.TokenError:
        pass

    return False

def _remove_trailing_commas(text):
    text = text.replace(", )", ")")
    text = text.replace(", ]", "]")
    text = text.replace(", }", "}")
    return text

def _try_join_block(source, lines, start, end):
    """
    Try to collapse lines[start:end+1] into one line.
    """
    block = lines[start:end + 1]
    if len(block) <= 1:
        return None
    if _has_comment(block):
        return None
    # Never touch multiline strings.
    for line_number in range(start + 1, end + 2):
        if _is_multiline_string( source, line_number + 1):
            return None
    indentation = _indent(block[0])
    content = " ".join( line.strip() for line in block )
    content = _remove_trailing_commas( content )
    candidate = indentation + content
    if len(candidate) > MAX_LINE_LENGTH:
        return None
    return candidate

def _delimiter_depth(line):
    """
    Calculate (), [] and {} balance while ignoring strings
    and comments.
    """
    depth = 0
    try:
        tokens = tokenize.generate_tokens( io.StringIO(line).readline )
        for token in tokens:
            if token.type in ( tokenize.STRING, tokenize.COMMENT):
                continue
            if token.string in "([{":
                depth += 1
            elif token.string in ")]}":
                depth -= 1
    except tokenize.TokenError:
        pass
    return depth

def _find_multiline_blocks(source, lines):
    """
    Find physical line ranges belonging to multiline
    parenthesized expressions.
    """
    blocks = []
    try:
        tokens = list( tokenize.generate_tokens( io.StringIO(source).readline ) )
    except tokenize.TokenError:
        return blocks
    stack = []
    pairs = { "(": ")", "[": "]", "{": "}"}
    for token in tokens:
        if token.string in pairs:
            stack.append( ( token.string, token.start[0] - 1) )
        elif token.string in pairs.values():
            if not stack:
                continue
            opening, start_line = stack.pop()
            end_line = token.end[0] - 1
            if end_line > start_line:
                blocks.append( ( start_line, end_line) )
    return blocks

def _compact_parentheses(source):
    """
    Collapse multiline (), [] and {} expressions whenever
    the resulting line fits MAX_LINE_LENGTH.
    """
    changed = True
    while changed:
        changed = False
        lines = source.splitlines()
        blocks = _find_multiline_blocks( source, lines)
        # Work from innermost / bottom-most blocks first.
        blocks.sort( key=lambda x: ( x[1] - x[0], x[0]) )
        for start, end in blocks:
            if start >= len(lines) or end >= len(lines):
                continue
            candidate = _try_join_block( source, lines, start, end)
            if candidate is None:
                continue
            new_lines = ( lines[:start] + [candidate] + lines[end + 1:] )
            new_source = "\n".join( new_lines ) + "\n"
            try:
                ast.parse(new_source)
            except SyntaxError:
                continue
            source = new_source
            changed = True
            break
    return source

def _compact_backslash_continuations(source):
    """
    Convert:

                value = something

    into:

        value = something
    """
    lines = source.splitlines()
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.rstrip().endswith("\\"):
            parts = [ line.rstrip()[:-1].rstrip() ]
            j = i + 1
            while j < len(lines):
                next_line = lines[j]
                if next_line.strip().startswith("#"):
                    break
                parts.append( next_line.strip() )
                if not next_line.rstrip().endswith("\\"):
                    break
                parts[-1] = ( parts[-1][:-1].rstrip() )
                j += 1
            candidate = ( _indent(line) + " ".join(parts) )
            if len(candidate) <= MAX_LINE_LENGTH:
                result.append(candidate)
                i = j + 1
                continue
        result.append(line.rstrip())
        i += 1
    return "\n".join(result) + "\n"

def _compact_indented_continuations(source):
    """
    Collapse simple implicit line continuations such as:

        value =
            something

    into:

        value = something

    Also handles:

        value = (
            something
        )

    after parentheses have already been compacted.
    """
    lines = source.splitlines()
    result = []
    i = 0
    continuation_operators = ( "=", "+", "-", "*", "/", "//", "%", "==", "!=", "<", ">", "<=", ">=", "|", "&", "^", "and", "or", "in", "is")
    while i < len(lines):
        current = lines[i]
        if ( i + 1 < len(lines) and current.strip() and not current.strip().startswith("#") ):
            stripped = current.rstrip()
            should_join = any( stripped.endswith(op) for op in continuation_operators )
            if should_join:
                next_line = lines[i + 1]
                if ( next_line.strip() and not next_line.strip().startswith("#") and not _is_multiline_string( source, i + 2) ):
                    candidate = ( _indent(current) + current.strip() + " " + next_line.strip() )
                    if len(candidate) <= MAX_LINE_LENGTH:
                        try:
                            test_lines = ( result + [candidate] + lines[i + 2:] )
                            test_source = ( "\n".join(test_lines) + "\n" )
                            ast.parse(test_source)
                            result.append(candidate)
                            i += 2
                            continue
                        except SyntaxError:
                            pass
        result.append( current.rstrip() )
        i += 1
    return "\n".join(result) + "\n"

def _remove_excess_blank_lines(source):
    """
    Reduce multiple consecutive blank lines.
    """
    lines = source.splitlines()
    result = []
    blank = False
    for line in lines:
        if not line.strip():
            if not blank:
                result.append("")
            blank = True
            continue
        result.append( line.rstrip() )
        blank = False
    while result and not result[0].strip():
        result.pop(0)
    while result and not result[-1].strip():
        result.pop()
    return "\n".join(result) + "\n"

def compact_python(source):
    """
    Compact Python code while preserving its semantics.
    """
    # Validate input first.
    ast.parse(source)
    source = _remove_excess_blank_lines( source )
    source = _compact_backslash_continuations( source )
    source = _compact_parentheses( source )
    source = _compact_indented_continuations( source )
    source = _compact_parentheses( source )
    # Validate final result.
    ast.parse(source)
    return source

def format_file(path, backup=False):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError( f"File not found: {path}" )
    if path.suffix != ".py":
        raise ValueError( f"Expected a Python file: {path}" )
    source = path.read_text( encoding="utf-8" )
    # Validate before modifying.
    ast.parse(source)
    if backup:
        backup_path = path.with_suffix( path.suffix + ".bak" )
        backup_path.write_text( source, encoding="utf-8" )
        print( f"Backup created: {backup_path}" )
    formatted = compact_python( source )
    path.write_text( formatted, encoding="utf-8" )
    print( f"Formatted: {path}" )

def main():
    if len(sys.argv) < 2:
        print( "Usage:" )
        print( "  python compact.py <file.py>" )
        print()
        print( "Optional backup:" )
        print( "  python compact.py <file.py> --backup" )
        sys.exit(1)
    path = sys.argv[1]
    backup = "--backup" in sys.argv[2:]
    try:
        format_file( path, backup=backup)
    except SyntaxError as e:
        print( f"Syntax error: {e}" )
        sys.exit(1)
    except Exception as e:
        print( f"Error: {e}" )
        sys.exit(1)

if __name__ == "__main__":
    main()
