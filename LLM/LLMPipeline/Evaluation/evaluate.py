import json
import os

from charset_normalizer.utils import is_cjk
from dotenv import load_dotenv
from openai import OpenAI

from LLM.Interface.activate_local_llm import activate_llm
from LLM.Interface.llm_call import llm_call


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# LOCAL LLM
CHAT_URL = "http://127.0.0.1:8080"

# REMOTE LLM
load_dotenv()

CLIENT = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

MODEL = os.environ.get(
    "OPENAI_MODEL",
    "gpt-4o-mini"
)

# WHICH LLM TO USE
IS_LOCAL = os.getenv(
    "IS_LOCAL",
    "False"
) == "True"




# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATA_MESH_DIR = os.getcwd()

LLM_DIR = os.path.join(DATA_MESH_DIR, "LLM")


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


OUTPUT_DIR_PATH=os.path.join(
    EVALUATION_DIR,
    "Output"
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
    os.path.dirname(LLM_DIR),
    "docker-compose",
    "opa",
    "policy.rego"
)


LLAMA_DIR = r"C:\Users\berta\BertaFiles\Project\DataMeshPoliciesLLM\LLM\LocalLLMIntelIpex\llama-cpp-ipex-llm-2.3.0b20250424-win"

activate_llm(LLAMA_DIR, IS_LOCAL, CHAT_URL,"Qwen2.5.1-Coder-7B-Instruct-Q4_K_M.gguf", '8080' )




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
# LLM Prompt
# ---------------------------------------------------------------------------


SYSTEM_PROMPT = """

You are an expert in:

- Trino authorization
- OPA policies
- Data Mesh security
- SQL authorization testing


Your task is to evaluate a failed or successful authorization test.

Determine who is wrong:

Possible values:

CORRECT_BEHAVIOR
TEST_ERROR
OPA_POLICY_ERROR
DATA_MESH_ERROR
TRINO_CONFIGURATION_ERROR
UNKNOWN


Rules:

- Compare expected_allowed with actual_allowed.
- Inspect OPA requests.
- Inspect user groups.
- Inspect Data Mesh structure.
- Inspect required Trino actions.

If expected=true but OPA denies:
check if the policy misses required permissions.

If the policy is wrong:
return a correction suggestion.

If SQL references missing resources:
classify DATA_MESH_ERROR.

If SQL is invalid:
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
# Evaluation
# ---------------------------------------------------------------------------


def evaluate_interaction(interaction,policy, data_mesh,users,actions,examples,is_local,chat_url=None,client=None,model=None):


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

        # send only the relevant parts
        "opa_requests": interaction["output"].get(
            "requests",
            []
        ),

        "data_mesh": data_mesh,

        "available_actions": actions,

        "examples": examples[:3]
    }

    messages = [

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
            "content": json.dumps(
                payload,
                indent=2
            )

        }

    ]

    prompt = json.dumps(
        messages,
        indent=2
    )

    response = llm_call(prompt,temperature=0,max_tokens=1200,is_local=is_local,chat_url=chat_url,client=client,model=model)

    response = response.strip()

    print("\n[LLM RAW RESPONSE]")
    print(response)
    print("--------------------")

    if not response:
        raise RuntimeError(
            "LLM returned empty response"
        )

    try:
        return json.loads(response)

    except json.JSONDecodeError:

        # Try extracting JSON if model added text
        start = response.find("{")
        end = response.rfind("}")

        if start != -1 and end != -1:

            json_part = response[start:end + 1]

            try:
                return json.loads(json_part)

            except Exception:
                pass

        raise RuntimeError(
            f"LLM returned invalid JSON:\n{response}"
        )



# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():


    global CLIENT
    print("=" * 60)
    print(" Authorization Evaluation")
    print("=" * 60)


    if IS_LOCAL:
        print("Using LOCAL LLM")
        CLIENT = None
    else:
        print(
            f"Using model: {MODEL}"
        )


    results = load_json(
        RESULT_PATH
    )


    policy = load_text(
        POLICY_PATH
    )


    data_mesh = load_json(
        DATA_MESH_PATH
    )


    users = load_json(
        USER_PATH
    )


    actions = load_json(
        ACTION_PATH
    )


    examples = load_json(
        EXAMPLES_PATH
    )


    evaluation = []


    for item in results["results"]:

        print(
            "\nEvaluating:",
            item["input"]["query"]
        )

        try:
            result = evaluate_interaction(interaction=item, policy=policy,data_mesh=data_mesh,users=users,actions=actions, examples=examples, is_local=IS_LOCAL, client=CLIENT, model=MODEL, chat_url=CHAT_URL )

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

    os.makedirs(OUTPUT_DIR_PATH, exist_ok=True)

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
        "\nSaved:",
        OUTPUT_PATH
    )



if __name__ == "__main__":

    main()