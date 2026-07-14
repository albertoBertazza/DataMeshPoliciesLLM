import requests
import json
import os

URL = "http://127.0.0.1:8080/completion"

CHECK_FOR_ACTION_PATH = os.path.join("Structure", "checkForAction.json")
INPUT_SCHEMA_PATH = os.path.join("Structure", "input.json")


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Loaded once at startup
CHECK_FOR_ACTION = load_json(CHECK_FOR_ACTION_PATH)   # action -> [checks...]
INPUT_SCHEMA = load_json(INPUT_SCHEMA_PATH)           # shape Trino sends to OPA

VALID_ACTIONS = list(CHECK_FOR_ACTION.keys())


# Loaded once at startup - these are the two files you described
CHECK_FOR_ACTION = load_json(CHECK_FOR_ACTION_PATH)   # action -> [checks...]
INPUT_SCHEMA = load_json(INPUT_SCHEMA_PATH)           # shape Trino sends to OPA

VALID_ACTIONS = list(CHECK_FOR_ACTION.keys())

# resource "type" -> the fields Trino puts under input.action.resource.<type>
RESOURCE_FIELD_MAP = {
    "catalog": ["catalogName"],
    "schema": ["catalogName", "schemaName"],
    "table": ["catalogName", "schemaName", "tableName"],
    "column": ["catalogName", "schemaName", "tableName", "columnName"],
}

# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

EXTRACT_PROMPT = """
You are an authorization policy parser.

The user will describe an access rule in natural language.

Interpret the sentence as an authorization policy.

Return ONLY valid JSON.

Never explain anything.
Never output markdown.

If the sentence does not specify a Trino action, use "*".

If the sentence does not specify the resource type, infer it.

Output format:

{
  "subject_attribute": "user" | "groups",
  "subject_value": "",
  "resource_type": "catalog" | "schema" | "table" | "column",
  "resource_values": {
      "catalogName": "",
      "schemaName": "",
      "tableName": "",
      "columnName": ""
  },
  "trino_action": "*"
}

Valid Trino actions:

{valid_actions}

Examples

Input:
alice can read table sales.orders

Output:
{
  "subject_attribute":"user",
  "subject_value":"alice",
  "resource_type":"table",
  "resource_values":{
      "catalogName":"sales",
      "schemaName":"",
      "tableName":"orders",
      "columnName":""
  },
  "trino_action":"*",

}

Input:
trino is the only user that must have access to the datamesh

Output:
{
  "subject_attribute":"user",
  "subject_value":"trino",
  "resource_type":"catalog",
  "resource_values":{
      "catalogName":"datamesh",
      "schemaName":"",
      "tableName":"",
      "columnName":""
  },
  "trino_action":"*",
}

Now parse:

{rule}
""".format(
    valid_actions=json.dumps(VALID_ACTIONS, indent=2)
)


MODEL_PROMPT_WRAPPER = """You are a strict information extraction system.

{prompt}
"""


def llm_call(prompt, temperature=0.0, n_predict=600):
    """Generic call to your llama-server"""
    response = requests.post(
        URL,
        json={
            "prompt": MODEL_PROMPT_WRAPPER.format(prompt=prompt),
            "temperature": temperature,
            "n_predict": n_predict,
            "stop": ["User:", "Rule:"],
        },
    )

    response.raise_for_status()
    return response.json()["content"]



# ---------------------------------------------------------------------------
# Rego generation
# ---------------------------------------------------------------------------

def build_rego(entities):
    subject_attr = entities["subject_attribute"]
    subject_val = entities["subject_value"]
    trino_action = entities["trino_action"]
    resource_type = entities["resource_type"]
    resource_values = entities.get("resource_values", {})

    if trino_action != "*" and trino_action not in CHECK_FOR_ACTION:
        raise ValueError(
            f"'{trino_action}' is not a known Trino action. "
            f"Valid actions: {VALID_ACTIONS}"
        )

    checks = CHECK_FOR_ACTION.get(trino_action, [])

    if trino_action == "*":
        operation_check = ""
    else:
        checks_set = ", ".join(f'"{c}"' for c in checks)
        operation_check = f"input.action.operation in {{{checks_set}}}"

    if trino_action != "*" and not checks:
        raise ValueError(
            f"'{trino_action}' has no associated OPA checks defined."
        )

    # --- identity match -----------------------------------------------
    if subject_attr == "groups":
        identity_check = f'input.context.identity.groups[_] == "{subject_val}"'
    else:
        identity_check = f'input.context.identity.user == "{subject_val}"'


    # --- resource match, following input.json's real shape -------------
    resource_lines = []
    fields = RESOURCE_FIELD_MAP.get(resource_type, [])
    for field in fields:
        val = resource_values.get(field)
        if val:
            resource_lines.append(
                f'    input.action.resource.{resource_type}.{field} == "{val}"'
            )
    resource_block = "\n".join(resource_lines)

    body_lines = [identity_check]

    if operation_check:
        body_lines.append(operation_check)

    body_lines.extend(resource_lines)

    body = "\n".join(f"    {line}" for line in body_lines)

    return f"""package authz

import future.keywords.if
import future.keywords.in

default allow := false

# Trino action "{trino_action}" triggers these OPA checks: {checks}
allow if {{
{body}
}}
"""


# ---------------------------------------------------------------------------
# Extraction / interpretation
# ---------------------------------------------------------------------------

def extract_entities(rule):
    prompt = EXTRACT_PROMPT.replace("{rule}", rule)
    raw = llm_call(prompt, temperature=0.0)

    print("\n[RAW MODEL OUTPUT]\n", raw)  # DEBUG (important)

    raw = raw.strip()

    start = raw.find("{")
    end = raw.rfind("}")

    if start == -1 or end == -1:
        raise ValueError("No JSON found in model output")

    json_str = raw[start:end + 1]

    return json.loads(json_str)


def stream_thinking(rule):
    """Simple (non-streaming) version for your server"""
    response = llm_call(
        f"In one sentence, explain this Trino access rule: {rule}",
        temperature=0.2,
        n_predict=200,
    )

    print("\n[Interpretation]")
    print(response.strip())


def process_rule(rule):
    stream_thinking(rule)

    print("\n[Extracting entities...]")

    try:
        entities = extract_entities(rule)

        print(f"  subject           : {entities['subject_attribute']} == \"{entities['subject_value']}\"")
        print(f"  trino_action      : {entities['trino_action']}")
        print(f"  associated checks : {CHECK_FOR_ACTION.get(entities['trino_action'])}")
        print(f"  resource_type     : {entities['resource_type']}")
        print(f"  resource_values   : {entities.get('resource_values')}")

    except Exception as e:
        print("  Failed to parse entities:", e)
        return

    try:
        policy = build_rego(entities)
    except ValueError as e:
        print("  Failed to build policy:", e)
        return

    print("\n--- Generated OPA Policy ---")
    print(policy)
    print("----------------------------")

    filename = f"policy_{rule[:30].replace(' ', '_')}.rego"
    # add this file in output directory
    output_dir = "output/rego_policies"
    filename = os.path.join(output_dir, filename)

    os.makedirs(output_dir, exist_ok=True)

    with open(filename, "w") as f:
        f.write(policy)

    print(f"Saved to: {filename}")


# --- MAIN LOOP ---
if __name__ == "__main__":
    print("=" * 50)
    print(" OPA Policy Generator — Local Qwen (Intel Arc)")
    print(f" Loaded {len(VALID_ACTIONS)} action types from {CHECK_FOR_ACTION_PATH}")
    print("=" * 50)

    while True:
        rule = input("\nRule: ").strip()

        if rule.lower() in ("exit", "quit"):
            break

        if rule:
            process_rule(rule)