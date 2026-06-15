import requests
import json

URL = "http://127.0.0.1:8080/completion"

EXTRACT_PROMPT = """You are a strict JSON extraction engine.

RULE:
Return ONLY valid JSON.
No explanations.
No markdown.
No extra text.

If you do not follow this format, your output is invalid.

Extract from this rule:

{rule}

Output schema:
{{
  "subject": "",
  "subject_attribute": "",
  "subject_value": "",
  "resource": "",
  "action": ""
}}
"""


MODEL_PROMPT_WRAPPER = """You are a strict information extraction system.

{prompt}
"""


def llm_call(prompt, temperature=0.0, n_predict=300):
    """Generic call to your llama-server"""
    response = requests.post(
        URL,
        json={
            "prompt": MODEL_PROMPT_WRAPPER.format(prompt=prompt),
            "temperature": temperature,
            "n_predict": n_predict,
            "stop": ["User:", "Rule:"]
        }
    )

    response.raise_for_status()
    return response.json()["content"]



def build_rego(entities):
    subject_attr = entities["subject_attribute"]
    subject_val  = entities["subject_value"]
    resource     = entities["resource"].replace(" ", "_")
    action       = entities["action"]
    subject      = entities["subject"]

    return f"""package authz

import future.keywords.if

default allow := false

allow if {{
    input.user.{subject_attr} == "{subject_val}"
    input.resource.type == "{resource}"
    input.action == "{action}"
}}
"""

def extract_entities(rule):
    raw = llm_call(EXTRACT_PROMPT.format(rule=rule), temperature=0.0)

    print("\n[RAW MODEL OUTPUT]\n", raw)  # DEBUG (important)

    raw = raw.strip()

    # try to extract JSON safely
    start = raw.find("{")
    end = raw.rfind("}")

    if start == -1 or end == -1:
        raise ValueError("No JSON found in model output")

    json_str = raw[start:end+1]

    return json.loads(json_str)


def stream_thinking(rule):
    """Simple (non-streaming) version for your server"""
    response = llm_call(
        f"In one sentence, explain this rule: {rule}",
        temperature=0.2,
        n_predict=80
    )

    print("\n[Interpretation]")
    print(response.strip())


def process_rule(rule):
    stream_thinking(rule)

    print("\n[Extracting entities...]")

    try:
        entities = extract_entities(rule)

        print(f"  subject_attribute : {entities['subject_attribute']} == \"{entities['subject_value']}\"")
        print(f"  resource          : {entities['resource']}")
        print(f"  action            : {entities['action']}")

    except Exception as e:
        print("  Failed to parse entities:", e)
        return

    policy = build_rego(entities)

    print("\n--- Generated OPA Policy ---")
    print(policy)
    print("----------------------------")

    filename = f"policy_{rule[:30].replace(' ', '_')}.rego"
    with open(filename, "w") as f:
        f.write(policy)

    print(f"Saved to: {filename}")


# --- MAIN LOOP ---
print("=" * 50)
print(" OPA Policy Generator — Local Qwen (Intel Arc)")
print("=" * 50)

while True:
    rule = input("\nRule: ").strip()

    if rule.lower() in ("exit", "quit"):
        break

    if rule:
        process_rule(rule)