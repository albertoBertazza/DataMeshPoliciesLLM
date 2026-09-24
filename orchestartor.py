import subprocess

from numpy.f2py.auxfuncs import throw_error

from Function.jsonHelper import load_json
from LLM.Interface.activate_local_llm import activate_llm
from LLM.LLMPipeline.IndexCreation.Rewrite.gen_index_rewrite import gen_index_rewrite
from LLM.LLMPipeline.IndexCreation.index_creator import ( reload_indexes)
from Pipelines.A_GenerationPipeline.generation import ( process_rule)
from Pipelines.B_TestAndEvaluationPipeline.C_TestEvaluation.evaluate_test import ( testEvaluation)

from Pipelines.costantPath import (
    CHECK_FOR_ACTION_PATH,
    SECURITY_GROUPS_PATH,
    DATA_MESH_STRUCTURE_PATH,
    EMBEDDING_URL,
    CLIENT,
    IS_LOCAL,
    EMBEDDING_MODEL,
    LOCAL_EMBEDDING_MODEL,
    LLAMA_DIR,
    CHAT_URL,
    LOCAL_CHAT_MODEL,
    DATABASE_REWRITE_RULE_FILE,
    INDEXED_REWRITE_RULE_PATH, DOCKER_COMPOSE_PATH, MODEL, EXAMPLE_RULES
)

from reset_rego import delete_files_generated

# ==========================================================
# LOAD STRUCTURE
# ==========================================================

CHECK_FOR_ACTION = load_json( CHECK_FOR_ACTION_PATH )
SECURITY_GROUPS = load_json( SECURITY_GROUPS_PATH )
DATA_MESH = load_json( DATA_MESH_STRUCTURE_PATH )

# ==========================================================
# LLM CONFIG
# ==========================================================

activate_llm(LLAMA_DIR, IS_LOCAL, CHAT_URL, LOCAL_CHAT_MODEL, "8080")

activate_llm( LLAMA_DIR, IS_LOCAL, EMBEDDING_URL, LOCAL_EMBEDDING_MODEL, "8081", other_params=" --embedding")

# ==========================================================
# INDEXES
# ==========================================================



INDEX_REWRITE_RULE = reload_indexes( IS_LOCAL, embedding_url=EMBEDDING_URL, client=CLIENT, embedding_model=EMBEDDING_MODEL, database_path=DATABASE_REWRITE_RULE_FILE,index_path=INDEXED_REWRITE_RULE_PATH,filename="rewrite_rule_example", gen_index_function=gen_index_rewrite)



def restart_opa() -> None:

    try:

        subprocess.run(
            [
                "docker",
                "compose",
                "restart",
                "opa",
            ],
            cwd=DOCKER_COMPOSE_PATH,
            check=True,
        )

        print(
            "OPA restarted successfully."
        )

    except subprocess.CalledProcessError as error:

        print(
            f"Failed to restart OPA: {error}"
        )


# ==========================================================
# PIPELINE
# ==========================================================


def start_pipelines(rule):
    # ======================================================
    # 1. GENERATE OPA POLICY
    # ======================================================

    success = process_rule(
        rule_passed=rule,
        index_rewrite_rule=INDEX_REWRITE_RULE,
        check_for_action=CHECK_FOR_ACTION,
        data_mesh=DATA_MESH,
        security_groups=SECURITY_GROUPS,
        is_local=IS_LOCAL,
        chat_url=CHAT_URL,
        embedding_url=EMBEDDING_URL,
        client=CLIENT,
        model=MODEL,
        embedding_model=EMBEDDING_MODEL,
    )

    if not success:
        print("\nPolicy pipeline failed.")
        return

    print("\n" + "=" * 70)
    print("POLICY PIPELINE COMPLETED")
    print("=" * 70)

    restart_opa()

    # ======================================================
    # 4. RESOLVE + GENERATE + EXECUTE + EVALUATE
    # ======================================================
    evaluation_report = testEvaluation()

    # ======================================================
    # 5. PRINT SUMMARY
    # ======================================================

    summary = evaluation_report.get("summary", {}, )
    print("\n" + "=" * 70)
    print("AUTHORIZATION EVALUATION")
    print("=" * 70)
    print(f"Total tests:  {summary.get('total', 0)}")
    print(f"Passed:       {summary.get('passed', 0)}")
    print(f"Failed:       {summary.get('failed', 0)}")
    print(f"Success:      {summary.get('success', False)}")
    print("=" * 70)
    return summary



if __name__ == "__main__":

    print("=" * 60)
    print(" DATA MESH POLICY PIPELINE")
    print("=" * 60)

    # Delete all generated .rego files
    delete_files_generated()

    # create and test all rule in the original set

    for rule in EXAMPLE_RULES:
        print("=" * 50)
        print(" EXAMPLE RULE " + rule)
        print("=" * 50)
        summary = start_pipelines(rule)

        if summary.get('success', False):
            throw_error(f"Not matched rule expectation: {rule}")

    while True:

        rule = input( "\nRule: " ).strip()

        if rule.lower() in ( "exit", "quit"):
            break

        if not rule:
            continue

        start_pipelines(rule)

