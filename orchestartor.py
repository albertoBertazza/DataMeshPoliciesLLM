from Function.jsonHelper import load_json
from LLM.Interface.activate_local_llm import activate_llm
from LLM.LLMPipeline.IndexCreation.EvaluationTest import gen_index_evaluation
from LLM.LLMPipeline.IndexCreation.index_creator import reload_indexes
from Pipelines.C_EvaluationTestResultPipeline.A_TestExecution.run_test_trino import launch_test
from Pipelines.C_EvaluationTestResultPipeline.B_TestEvaluation import evaluate_test

from LLM.LLMPipeline.IndexCreation.Rewrite import gen_index_rewrite
from Pipelines.A_GenerationPipeline.generation import process_rule
# from Pipelines.B_TestGenerationPipeline.test_generator import generate_test
from Pipelines.costantPath import CHECK_FOR_ACTION_PATH, SECURITY_GROUPS_PATH, \
    DATA_MESH_STRUCTURE_PATH, USER_CREDENTIALS_PATH, INPUT_STRUCTURE_PATH, EMBEDDING_URL, CLIENT, IS_LOCAL, \
    EMBEDDING_MODEL, LOCAL_EMBEDDING_MODEL, LLAMA_DIR, CHAT_URL, LOCAL_CHAT_MODEL, \
    MODEL, DATABASE_REWRITE_RULE_FILE, INDEXED_REWRITE_RULE_PATH, DATABASE_EVALUATION_TEST_FILE, \
    INDEXED_EVALUATION_TEST_PATH

from reset_rego import delete_files_generated

# ==========================================================
# LOAD STRUCTURE
# ==========================================================

CHECK_FOR_ACTION = load_json(
    CHECK_FOR_ACTION_PATH
)

INPUT_SCHEMA = load_json(
    INPUT_STRUCTURE_PATH
)

SECURITY_GROUPS = load_json(
    SECURITY_GROUPS_PATH
)

DATA_MESH = load_json(
    DATA_MESH_STRUCTURE_PATH
)

USER_CREDENTIALS = load_json(
    USER_CREDENTIALS_PATH
)

INPUT_STRUCTURE = load_json(
    INPUT_STRUCTURE_PATH
)

# ==========================================================
# LLM CONFIG
# ==========================================================

activate_llm(
    LLAMA_DIR,
    IS_LOCAL,
    CHAT_URL,
    LOCAL_CHAT_MODEL,
    "8080"
)


activate_llm(
    LLAMA_DIR,
    IS_LOCAL,
    EMBEDDING_URL,
    LOCAL_EMBEDDING_MODEL,
    "8081",
    other_params=" --embedding"
)



# ==========================================================
# INDEXES
# ==========================================================

INDEX_REWRITE_RULE = reload_indexes( IS_LOCAL, embedding_url=EMBEDDING_URL, client=CLIENT, embedding_model=EMBEDDING_MODEL, database_path=DATABASE_REWRITE_RULE_FILE,index_path=INDEXED_REWRITE_RULE_PATH,filename="rewrite_rule_example", gen_index_function=gen_index_rewrite)


# ==========================================================
# PIPELINE
# ==========================================================

if __name__ == "__main__":

    print("=" * 60)
    print(" DATA MESH POLICY PIPELINE")
    print("=" * 60)

    # Delete all .rego files inside docker-compose/opa
    delete_files_generated()

    while True:

        rule = input(
            "\nRule: "
        ).strip()


        if rule.lower() in (
            "exit",
            "quit"
        ):
            break


        if not rule:
            continue



        # -------------------------------
        # Generate OPA policy
        # -------------------------------

        success, result, explanation = process_rule(
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


        if not result:
            continue



        # -------------------------------
        # Generate Trino tests
        # -------------------------------
        #TODO
        # generate_test(
        #     explanation,
        #     data_mesh=DATA_MESH,
        #     user_credentials=USER_CREDENTIALS,
        #     is_local=IS_LOCAL,
        #     chat_url=CHAT_URL,
        #     embedding_url=EMBEDDING_URL,
        #     client=CLIENT,
        #     model=MODEL,
        #     embedding_model=EMBEDDING_MODEL
        # )



        # -------------------------------
        # Execute Trino tests
        # -------------------------------

        launch_test()



        # -------------------------------
        # Evaluate results
        # -------------------------------

        # evaluate_test(
        #     data_mesh=DATA_MESH,
        #     users=USER_CREDENTIALS,
        #     actions=CHECK_FOR_ACTION,
        #     policy_path=POLICY_PATH,
        #     examples_path=EVALUATION_EXAMPLES_PATH,
        #     is_local=IS_LOCAL,
        #     chat_url=CHAT_URL,
        #     client=CLIENT,
        #     model=MODEL
        # )