from typing import Dict, Any
import json
from Pipelines.A_GenerationPipeline.A_Rewrite.LLM_rule_rewrite import llm_explain
from Pipelines.B_TestAndEvaluationPipeline.A_TestGeneration.Resolver.authorization_resolver import AuthorizationResolver
from Pipelines.costantPath import REWRITTEN_RULE_PATH, GENERATED_RULE_PATH, CHECK_FOR_ACTION_PATH, \
    DATA_MESH_STRUCTURE_PATH, ACTION_SQL_MAPPING_PATH, USER_CREDENTIALS_PATH, IS_LOCAL, CHAT_URL, EMBEDDING_URL, CLIENT, \
    MODEL, EMBEDDING_MODEL
from orchestartor import INDEX_REWRITE_RULE, CHECK_FOR_ACTION, DATA_MESH, SECURITY_GROUPS


def check_action_allowed(
    rule_passed: str,
    index_rewrite_rule,
    check_for_action: Dict[str, Any],
    data_mesh: Dict[str, Any],
    security_groups: Any,
    is_local: bool = False,
    chat_url: str = '',
    embedding_url: str = '',
    client=None,
    model: str = '',
    embedding_model: str = ''
):
    # ========================================================================
    # 1. Explanation
    # ========================================================================

    print("\n[ 1. LLM rule rewrite]")

    try:

        explanation = llm_explain(
            rule_passed,
            index_rewrite_rule,
            data_mesh,
            security_groups,
            list(check_for_action.keys()),
            is_local=is_local,
            chat_url=chat_url,
            embedding_url=embedding_url,
            client=client,
            model=model,
            embedding_model=embedding_model,
        )

    except Exception as error:
        print("Explanation failed:", error)
        return False

    if not explanation.get("existSecureGroup", False):
        print("Invalid security group.")
        print("llm_feedback:", explanation.get("llm_feedback", ""))
        return False

    if not explanation.get("pathExistOnDataMeshStructure", False):
        print("Resource path does not exist.")
        print("llm_feedback:", explanation.get("llm_feedback", ""))
        return False

    if not explanation.get("actionExist", False):
        print("Action does not exist.")
        print("llm_feedback:", explanation.get("llm_feedback", ""))
        return False

    print("#" + "=" * 60)
    print("# Do you mean? ")
    print("#\t" + explanation.get("text", ""))
    print("#" + "=" * 60)

    answer = ""
    while answer != "y" and answer != "n":
        answer = input("Do you wanna accept this interpretation? [y/n]: ").strip().lower()

    if answer == "y":
        print(json.dumps(explanation, indent=2, ensure_ascii=False))
        # =========================================================
        # 1. CREATE RESOLVER
        # =========================================================
        resolver = AuthorizationResolver(REWRITTEN_RULE_PATH, GENERATED_RULE_PATH, CHECK_FOR_ACTION_PATH)

        # =========================================================
        # 2. RESOLVE
        # =========================================================
        resolved = resolver.resolve()
    return None



if __name__ == "__main__":
    while True:

        rule = input( "\nRule: " ).strip()

        if rule.lower() in ( "exit", "quit"):
            break

        if not rule:
            continue

        check_action_allowed(
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
            embedding_model=EMBEDDING_MODEL
        )