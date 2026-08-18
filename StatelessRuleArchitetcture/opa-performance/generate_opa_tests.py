import json
import os
import re
from pathlib import Path

import requests
from dotenv import load_dotenv
from openai import OpenAI

from LLM.Interface.activate_local_llm import activate_llm


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CHAT_URL = "http://127.0.0.1:8080"

OPA_URL = "http://localhost:8181"

load_dotenv()

CLIENT = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

MODEL = os.environ.get(
    "OPENAI_MODEL",
    "gpt-4o-mini"
)

IS_LOCAL = os.getenv(
    "IS_LOCAL",
    "False"
) == "True"

LLAMA_DIR = os.getenv(
    "LLAMA_DIR",
    r"C:\Users\berta\BertaFiles\Project\DataMeshPoliciesLLM"
)

LOCAL_CHAT_MODEL = os.getenv(
    "LOCAL_CHAT_MODEL"
)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_DIR = Path.cwd()

while PROJECT_DIR.name != "DataMeshPoliciesLLM":

    parent = PROJECT_DIR.parent

    if parent == PROJECT_DIR:
        raise RuntimeError(
            "DataMeshPoliciesLLM folder not found"
        )

    PROJECT_DIR = parent


OPA_DIR = (
    PROJECT_DIR
    / "StatelessRuleArchitetcture"
    / "docker-opa-stateless"
    / "opa"
)


OUTPUT_DIR = (
    PROJECT_DIR
    / "StatelessRuleArchitetcture"
    / "opa-performance"
    / "generated"
)


# ---------------------------------------------------------------------------
# Rego
# ---------------------------------------------------------------------------

def load_rego_files():

    files = list(
        OPA_DIR.rglob("*.rego")
    )

    policies = []

    for path in files:

        try:

            content = path.read_text(
                encoding="utf-8"
            )

        except UnicodeDecodeError:

            content = path.read_text(
                encoding="utf-8-sig"
            )

        policies.append({
            "file": str(path),
            "relative_file": str(
                path.relative_to(OPA_DIR)
            ),
            "content": content
        })

    return policies


def build_rego_context():

    policies = load_rego_files()

    if not policies:
        raise RuntimeError(
            f"No .rego files found in {OPA_DIR}"
        )

    sections = []

    for policy in policies:

        sections.append(
            f"""
============================================================
FILE: {policy["relative_file"]}
============================================================

{policy["content"]}
"""
        )

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# LLM prompt
# ---------------------------------------------------------------------------

def build_prompt(
    rego_context,
    number_of_tests=100
):

    return f"""
You are generating authorization test cases for Open Policy Agent (OPA).

The OPA policies below are the AUTHORITATIVE source of truth.

Do NOT invent permissions.

You must inspect the Rego policies and generate requests that exercise
both allowed and denied authorization decisions.

Generate exactly {number_of_tests} test cases.

The purpose is also performance evaluation, so avoid producing identical
requests repeatedly.

Generate cases covering:

1. Clearly allowed requests.
2. Clearly denied requests.
3. Boundary cases.
4. Wrong security group.
5. Wrong catalog.
6. Wrong schema.
7. Wrong table.
8. Wrong action.
9. Missing fields where meaningful.
10. Combinations of valid and invalid attributes.
11. Cases that exercise filters if the policies contain them.
12. Cases that exercise different branches of the Rego policies.

IMPORTANT:

- Only use values that are supported by the Rego policies or the provided
  policy context.
- Do not assume that an action is allowed merely because its name sounds
  reasonable.
- If the policy does not grant an action, generate it as a denied case.
- Expected authorization must be inferred from the Rego.
- The input must be directly usable as the JSON "input" object in an OPA
  request.

Return ONLY valid JSON.

The result must have this structure:

{{
    "tests": [
        {{
            "id": "unique_test_id",
            "description": "description",
            "expected": true,
            "input": {{
                "...": "..."
            }}
        }}
    ]
}}

Do not include markdown.
Do not include ```json.
Do not include explanations.

============================================================
OPA POLICIES
============================================================

{rego_context}
"""


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def call_llm(
    prompt,
    is_local,
    chat_url=None,
    client=None,
    model=None
):

    if is_local:

        response = requests.post(
            f"{chat_url}/v1/chat/completions",
            json={
                "model": model or "local",
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.1
            },
            timeout=300
        )

        response.raise_for_status()

        data = response.json()

        return (
            data["choices"][0]["message"]["content"]
        )

    response = client.chat.completions.create(
        model=model,
        temperature=0.1,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.choices[0].message.content


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------

def parse_llm_json(text):

    text = text.strip()

    # Remove accidental markdown fences.

    text = re.sub(
        r"^```json\s*",
        "",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"^```\s*",
        "",
        text
    )

    text = re.sub(
        r"\s*```$",
        "",
        text
    )

    return json.loads(text)


# ---------------------------------------------------------------------------
# Generate
# ---------------------------------------------------------------------------

def generate_opa_tests(
    number_of_tests=100,
    is_local=IS_LOCAL,
    chat_url=CHAT_URL,
    client=CLIENT,
    model=MODEL
):

    print("=" * 60)
    print(" OPA Interaction Test Generator")
    print("=" * 60)

    print()
    print(f"OPA policy directory: {OPA_DIR}")
    print(f"Generating {number_of_tests} tests")

    rego_context = build_rego_context()

    print(
        f"Loaded {len(load_rego_files())} Rego files"
    )

    prompt = build_prompt(
        rego_context,
        number_of_tests
    )

    print()
    print("Generating tests with LLM...")

    raw = call_llm(
        prompt,
        is_local,
        chat_url,
        client,
        model
    )

    try:

        result = parse_llm_json(raw)

    except Exception as e:

        print()
        print("LLM returned invalid JSON.")
        print(raw)

        raise RuntimeError(
            f"Could not parse generated tests: {e}"
        )

    tests = result.get(
        "tests",
        []
    )

    if not isinstance(tests, list):

        raise RuntimeError(
            "LLM response does not contain a tests array"
        )

    print(
        f"Generated {len(tests)} tests"
    )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    output_file = (
        OUTPUT_DIR
        / f"opa_tests_{number_of_tests}.json"
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            result,
            f,
            indent=4
        )

    print()
    print(
        f"Saved: {output_file}"
    )

    return result


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    if IS_LOCAL:

        activate_llm(
            LLAMA_DIR,
            IS_LOCAL,
            CHAT_URL,
            LOCAL_CHAT_MODEL,
            "8080"
        )

    generate_opa_tests(
        number_of_tests=100
    )