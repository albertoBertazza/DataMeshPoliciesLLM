import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from LLM.Interface.activate_local_llm import activate_llm
from LLM.Interface.llm_call import llm_call


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CHAT_URL = "http://127.0.0.1:8080"

load_dotenv()

CLIENT = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

MODEL = os.getenv(
    "OPENAI_MODEL",
    "gpt-4o-mini"
)

IS_LOCAL = os.getenv(
    "IS_LOCAL",
    "False"
) == "True"


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATA_MESH_DIR = os.getcwd()

LLM_DIR = os.path.join(
    DATA_MESH_DIR,
    "LLM"
)

STRUCTURE_DIR = os.path.join(
    LLM_DIR,
    "Structure"
)


EVALUATION_DIR = os.path.join(
    LLM_DIR,
    "LLMPipeline",
    "Evaluation"
)


RESULT_PATH = os.path.join(
    EVALUATION_DIR,
    "ResultInteraction",
    "test_results.json"
)


OUTPUT_PATH = os.path.join(
    EVALUATION_DIR,
    "Output",
    "evaluation_result.json"
)


DATA_MESH_PATH = os.path.join(
    STRUCTURE_DIR,
    "data_mesh.json"
)


USER_PATH = os.path.join(
    STRUCTURE_DIR,
    "user_credentials.json"
)


ACTION_PATH = os.path.join(
    STRUCTURE_DIR,
    "checkForAction.json"
)


EXAMPLES_PATH = os.path.join(
    EVALUATION_DIR,
    "Examples",
    "evaluation_examples.json"
)


POLICY_PATH = os.path.join(
    DATA_MESH_DIR,
    "docker-compose",
    "opa",
    "policy.rego"
)


LLAMA_DIR = r"C:\Users\berta\BertaFiles\Project\DataMeshPoliciesLLM\LLM\LocalLLMIntelIpex\llama-cpp-ipex-llm-2.3.0b20250424-win"

LOCAL_CHAT_MODEL = os.getenv(
    "LOCAL_CHAT_MODEL"
)

activate_llm(
    LLAMA_DIR,
    IS_LOCAL,
    CHAT_URL,
    LOCAL_CHAT_MODEL,
    "8080"
)


# ---------------------------------------------------------------------------
# Utils
# ---------------------------------------------------------------------------

def load_json(path):
    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)



def load_text(path):
    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return f.read()



# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """

You are an expert in:

- Trino authorization
- OPA policies
- Data Mesh security
- SQL authorization testing


Evaluate the authorization test.

Possible classifications:

CORRECT_BEHAVIOR
TEST_ERROR
OPA_POLICY_ERROR
DATA_MESH_ERROR
TRINO_CONFIGURATION_ERROR
UNKNOWN


Rules:

- Compare expected_allowed and actual_allowed.
- Inspect OPA requests.
- Inspect user groups.
- Inspect Data Mesh structure.
- Inspect required Trino actions.

If SQL references missing resources:
classify DATA_MESH_ERROR.

If SQL syntax is invalid:
classify TEST_ERROR.

Return ONLY JSON:

{
 "classification":"",
 "reason":"",
 "policy_fix":"",
 "confidence":0.0
}

"""


# ---------------------------------------------------------------------------
# Interaction evaluation
# ---------------------------------------------------------------------------

def evaluate_interaction(
    interaction,
    policy,
    data_mesh,
    users,
    actions,
    examples,
    is_local,
    chat_url=None,
    client=None,
    model=None
):

    username = interaction["input"]["username"]


    user_info = next(
        (
            u for u in users
            if u["username"] == username
        ),
        None
    )


    payload = {

        "interaction": interaction,

        "user_info": user_info,

        "opa_requests":
            interaction["output"].get(
                "requests",
                []
            ),

        "data_mesh": data_mesh,

        "available_actions": actions,

        "examples": examples[:3]
    }


    prompt = json.dumps(
        [
            {
                "role": "system",
                "content":
                    SYSTEM_PROMPT
                    +
                    "\n\nOPA POLICY:\n"
                    +
                    policy
            },

            {
                "role": "user",
                "content":
                    json.dumps(
                        payload,
                        indent=2
                    )
            }
        ],
        indent=2
    )


    response = llm_call(
        prompt,
        temperature=0,
        max_tokens=1200,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model
    )


    response = response.strip()

    print("\n[LLM RAW RESPONSE]")
    print(response)


    try:
        return json.loads(response)

    except json.JSONDecodeError:

        start = response.find("{")
        end = response.rfind("}")

        if start != -1 and end != -1:
            return json.loads(
                response[start:end+1]
            )

        raise RuntimeError(
            response
        )



# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def evaluate_test(
    data_mesh,
    users,
    actions,
    policy_path,
    examples_path=None,
    is_local=False,
    chat_url=None,
    client=None,
    model=None
):

    print("=" * 60)
    print("Authorization Evaluation")
    print("=" * 60)


    if client is None:
        client = CLIENT

    if model is None:
        model = MODEL


    policy = load_text(
        policy_path
    )


    results = load_json(
        RESULT_PATH
    )


    if examples_path:
        examples = load_json(
            examples_path
        )
    else:
        examples = []


    evaluation = []


    for item in results["results"]:

        print(
            "\nEvaluating:",
            item["input"]["query"]
        )


        try:

            result = evaluate_interaction(
                interaction=item,
                policy=policy,
                data_mesh=data_mesh,
                users=users,
                actions=actions,
                examples=examples,
                is_local=is_local,
                chat_url=chat_url,
                client=client,
                model=model
            )


        except Exception as e:

            result = {
                "classification": "UNKNOWN",
                "reason": str(e),
                "policy_fix": "",
                "confidence": 0
            }


        evaluation.append(
            {
                "input": item["input"],
                "evaluation": result
            }
        )


    output = {
        "evaluation": evaluation
    }


    os.makedirs(
        os.path.dirname(OUTPUT_PATH),
        exist_ok=True
    )


    with open(
        OUTPUT_PATH,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output,
            f,
            indent=2,
            ensure_ascii=False
        )


    print(
        "Saved:",
        OUTPUT_PATH
    )


# ---------------------------------------------------------------------------
# Standalone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":


    data_mesh = load_json(
        DATA_MESH_PATH
    )


    users = load_json(
        USER_PATH
    )


    actions = load_json(
        ACTION_PATH
    )


    evaluate_test(
        data_mesh=data_mesh,
        users=users,
        actions=actions,
        policy_path=POLICY_PATH,
        examples_path=EXAMPLES_PATH,
        is_local=IS_LOCAL,
        chat_url=CHAT_URL,
        client=CLIENT,
        model=MODEL
    )