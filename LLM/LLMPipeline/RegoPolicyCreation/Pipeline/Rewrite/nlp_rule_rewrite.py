import json
import numpy as np

from LLM.Interface.embedding_call import embedding_call
from LLM.Interface.llm_call import llm_call


# ---------------------------------------------------------------------------
# Similarity
# ---------------------------------------------------------------------------

def cosine_similarity(a, b):
    denominator = (
        np.linalg.norm(a) *
        np.linalg.norm(b)
    )

    if denominator == 0:
        return 0.0

    return np.dot(a, b) / denominator


# ---------------------------------------------------------------------------
# Retrieve examples
# ---------------------------------------------------------------------------

def find_best_examples(
    rule,
    index,
    is_local,
    n=3,
    embedding_url=None,
    client=None,
    embedding_model=None,
):
    query_embedding = embedding_call(
        text=rule,
        is_local=is_local,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model,
    )

    ranked = sorted(
        index,
        key=lambda example: cosine_similarity(
            query_embedding,
            example["embedding"],
        ),
        reverse=True,
    )

    return ranked[:n]


# ---------------------------------------------------------------------------
# LLM explanation
# ---------------------------------------------------------------------------

def llm_explain(
    rule,
    example_index,
    data_mesh_structure,
    security_groups,
    available_actions,
    is_local,
    n=3,
    chat_url=None,
    embedding_url=None,
    client=None,
    model=None,
    embedding_model=None,
):

    # -----------------------------------------------------------------------
    # Retrieve semantically similar examples
    # -----------------------------------------------------------------------

    examples = find_best_examples(
        rule,
        example_index,
        is_local,
        n=n,
        embedding_url=embedding_url,
        client=client,
        embedding_model=embedding_model,
    )

    # -----------------------------------------------------------------------
    # System prompt
    # -----------------------------------------------------------------------

    system_prompt = (
        "You are an expert in Trino access policies.\n\n"

        "Your task is to understand, explain and validate a user's natural "
        "language Trino access request.\n\n"

        "The user's request may describe an operation using natural language. "
        "The user does NOT necessarily provide the exact Trino action name. "
        "You must first understand what the user wants and then determine "
        "which available Trino action best represents that intent.\n\n"

        "You MUST independently validate three things:\n"
        "1. Security group / subject\n"
        "2. Data Mesh resource path\n"
        "3. Requested / inferred Trino action\n\n"

        "====================================================================\n"
        "SOURCE OF TRUTH\n"
        "====================================================================\n\n"

        "The following sources are authoritative:\n\n"

        "1. Existing Security Groups\n"
        "   Valid subjects MUST exist in this list.\n\n"

        "2. Existing Data Mesh Structure\n"
        "   Valid catalogs, schemas, tables and columns MUST exist in this "
        "structure.\n\n"

        "3. Available Actions\n"
        "   This is ONLY a list of valid Trino action names.\n"
        "   Every action selected by you MUST exist in this list.\n\n"

        "NEVER invent a catalog, schema, table, column, security group or "
        "action.\n\n"

        "====================================================================\n"
        "IMPORTANT: AVAILABLE ACTIONS\n"
        "====================================================================\n\n"

        "Available Actions contains ONLY action names.\n\n"

        "It is NOT a mapping between actions and permissions.\n"
        "Do NOT assume that an action has permissions because of its name.\n"
        "Do NOT invent additional actions.\n\n"

        "For example, if Available Actions contains:\n"
        "\"ShowSchemas\"\n"
        "then ShowSchemas is valid.\n\n"

        "If Available Actions does NOT contain:\n"
        "\"SelectFromColumns\"\n"
        "then SelectFromColumns is NOT valid, even if an example contains "
        "that action.\n\n"

        "====================================================================\n"
        "UNDERSTAND USER INTENT BEFORE VALIDATING ACTION\n"
        "====================================================================\n\n"

        "The user may describe an action indirectly.\n"
        "You must understand the intended operation before deciding whether "
        "the action is valid.\n\n"

        "Examples of natural language intent:\n\n"

        "\"wants to see the schemas\"\n"
        "-> intent may correspond to ShowSchemas\n\n"

        "\"wants to see the tables\"\n"
        "-> intent may correspond to ShowTables\n\n"

        "\"wants to see the columns\"\n"
        "-> intent may correspond to ShowColumns\n\n"

        "\"wants to see how a table is created\"\n"
        "-> intent may correspond to ShowCreateTable\n\n"

        "\"wants to create a schema\"\n"
        "-> intent may correspond to CreateSchema\n\n"

        "\"wants to create a table\"\n"
        "-> intent may correspond to CreateTable\n\n"

        "\"wants to delete a table\"\n"
        "-> intent may correspond to DropTable\n\n"

        "\"wants to delete rows from a table\"\n"
        "-> intent may correspond to DeleteFromTable\n\n"

        "\"wants to insert data into a table\"\n"
        "-> intent may correspond to InsertIntoTable\n\n"

        "\"wants to update columns in a table\"\n"
        "-> intent may correspond to UpdateTableColumns\n\n"

        "\"wants to add a column\"\n"
        "-> intent may correspond to AddColumn\n\n"

        "\"wants to remove a column\"\n"
        "-> intent may correspond to DropColumn\n\n"

        "\"wants to rename a column\"\n"
        "-> intent may correspond to RenameColumn\n\n"

        "\"wants to truncate a table\"\n"
        "-> intent may correspond to TruncateTable\n\n"

        "These are examples of semantic interpretation only. "
        "They are NOT permissions and MUST still be checked against "
        "Available Actions.\n\n"

        "If the user's wording is ambiguous, do not invent an action. "
        "Use llm_feedback to explain what information is missing or suggest "
        "the closest valid interpretation using ONLY Available Actions.\n\n"

        "====================================================================\n"
        "SPECIAL CASE: 'ACCESS' / 'READ' / 'CONSULT'\n"
        "====================================================================\n\n"

        "Words such as 'access', 'read', 'consult', 'use' or 'look at' do not "
        "automatically correspond to a specific action.\n\n"

        "You must inspect the object being accessed and the available actions.\n\n"

        "For example:\n\n"

        "\"The Finance Manager can access the finance schema.\"\n\n"

        "means the user is referring to the schema resource, but the exact "
        "operation must be inferred from the available actions.\n\n"

        "If ShowSchemas is available, it may represent an intent to inspect "
        "schemas.\n\n"

        "If ShowCreateSchema is available and the user explicitly asks for "
        "the schema definition, that action may be appropriate.\n\n"

        "If no available action represents the requested operation, set "
        "actionExist=false and explain the problem in llm_feedback.\n\n"

        "Do NOT automatically assume that the generic word 'access' means "
        "a nonexistent action called AccessSchema or AccessCatalog.\n\n"

        "====================================================================\n"
        "SECURITY GROUP VALIDATION\n"
        "====================================================================\n\n"

        "If the subject/security group does not exist:\n"
        "- set existSecureGroup=false\n"
        "- keep the original subject in text\n"
        "- explain which security group is invalid\n"
        "- use llm_feedback to suggest valid security groups\n"
        "- use ONLY Existing Security Groups for corrections\n\n"

        "If the security group exists:\n"
        "- set existSecureGroup=true\n\n"

        "====================================================================\n"
        "RESOURCE VALIDATION\n"
        "====================================================================\n\n"

        "Validate catalogs, schemas, tables and columns hierarchically.\n\n"

        "A valid path must exist exactly in Data Mesh Structure.\n\n"

        "For example:\n\n"

        "iceberg.hr.employees\n\n"

        "is valid because:\n"
        "catalog iceberg exists\n"
        "schema hr exists inside iceberg\n"
        "table employees exists inside iceberg.hr\n\n"

        "If a column is specified, it must exist inside the specified table.\n\n"

        "If the catalog does not exist:\n"
        "- set pathExistOnDataMeshStructure=false\n"
        "- explain the invalid catalog\n"
        "- suggest valid catalogs\n\n"

        "If the schema does not exist inside the specified catalog:\n"
        "- set pathExistOnDataMeshStructure=false\n"
        "- explain the invalid schema\n"
        "- suggest schemas from that catalog\n\n"

        "If the table does not exist inside the specified catalog/schema:\n"
        "- set pathExistOnDataMeshStructure=false\n"
        "- explain the invalid table\n"
        "- suggest valid tables from that location\n\n"

        "If the column does not exist inside the specified table:\n"
        "- set pathExistOnDataMeshStructure=false\n"
        "- explain the invalid column\n"
        "- suggest valid columns from that table\n\n"

        "Do NOT silently replace invalid resources in text.\n"
        "The original request must remain represented in text.\n"
        "Corrections belong in llm_feedback.\n\n"

        "====================================================================\n"
        "ACTION VALIDATION\n"
        "====================================================================\n\n"

        "After understanding the user's intent, determine the intended "
        "Trino action.\n\n"

        "If the intended action exists in Available Actions:\n"
        "- set actionExist=true\n\n"

        "If the intended action does NOT exist in Available Actions:\n"
        "- set actionExist=false\n"
        "- explain which action the request appears to require\n"
        "- use llm_feedback to suggest the closest valid action(s) from "
        "Available Actions\n\n"

        "IMPORTANT:\n"
        "Do not mark an action as valid merely because the user's natural "
        "language sounds reasonable.\n"
        "The final action MUST exist literally in Available Actions.\n\n"

        "====================================================================\n"
        "LLM FEEDBACK\n"
        "====================================================================\n\n"

        "llm_feedback is the correction channel.\n\n"

        "If everything is valid:\n"
        "\"llm_feedback\": \"\"\n\n"

        "If something is invalid, llm_feedback must help the client correct "
        "the request.\n\n"

        "If multiple things are invalid, explain ALL of them.\n\n"

        "For example:\n\n"

        "The Guest wants to query iceberg.finance.asset.\n\n"

        "If Guest is invalid and asset does not exist, feedback should explain "
        "both problems and suggest valid alternatives.\n\n"

        "====================================================================\n"
        "OUTPUT FORMAT\n"
        "====================================================================\n\n"

        "Return ONLY a valid JSON object.\n"
        "Do not return markdown.\n"
        "Do not use ```.\n"
        "Do not return explanations outside JSON.\n\n"

        "The JSON MUST have exactly these fields:\n\n"

        "{\n"
        '  "text": "<explanation of the original request>",\n'
        '  "existSecureGroup": true,\n'
        '  "pathExistOnDataMeshStructure": true,\n'
        '  "actionExist": true,\n'
        '  "llm_feedback": ""\n'
        "}\n\n"

        "The llm_feedback field MUST always exist.\n\n"

        "====================================================================\n"
        "TEXT FIELD\n"
        "====================================================================\n\n"

        "The text field describes what you understood from the ORIGINAL "
        "request.\n\n"

        "Do NOT silently correct the request inside text.\n\n"

        "For example, if the user says:\n"
        "\"The Finance Manager wants to query iceberg.finance.asset.\"\n\n"

        "and asset does not exist, text should still describe asset as the "
        "requested table.\n\n"

        "The correction belongs in llm_feedback.\n\n"

        "====================================================================\n"
        "EXPLANATION STYLE\n"
        "====================================================================\n\n"

        "When a catalog.schema.table is present, explain it explicitly as:\n"
        "catalog: <catalog>, schema: <schema>, table: <table>.\n\n"

        "When a column is present, also mention the column.\n\n"

        "====================================================================\n"
        "EXAMPLE\n"
        "====================================================================\n\n"

        "Suppose the request is:\n"
        "\"The Analyst wants to query iceberg.sales.orders.\"\n\n"

        "and iceberg contains only hr and finance.\n\n"

        "A correct response is:\n\n"

        "{\n"
        '  "text": "The Analyst wants to query catalog iceberg, schema sales, table orders.",\n'
        '  "existSecureGroup": true,\n'
        '  "pathExistOnDataMeshStructure": false,\n'
        '  "actionExist": true,\n'
        '  "llm_feedback": "The schema \'sales\' does not exist in catalog \'iceberg\'. The available schemas are \'hr\' and \'finance\'. Correct the request by selecting a valid schema."\n'
        "}\n\n"

        "====================================================================\n"
        "AUTHORITATIVE DATA\n"
        "====================================================================\n\n"

        "### Existing Security Groups\n"
        f"{json.dumps(security_groups, indent=2)}\n\n"

        "### Available Actions\n"
        "This is ONLY a list of valid action names.\n"
        "Do NOT interpret it as a mapping of permissions.\n"
        f"{json.dumps(available_actions, indent=2)}\n\n"

        "### Existing Data Mesh Structure\n"
        f"{json.dumps(data_mesh_structure, indent=2)}\n"
    )

    messages = [
        {
            "role": "system",
            "content": system_prompt,
        }
    ]

    # -----------------------------------------------------------------------
    # Retrieved examples
    # -----------------------------------------------------------------------

    for example in examples:

        messages.append({
            "role": "system",
            "content": (
                "The following is a retrieved example.\n\n"
                "It is provided ONLY to demonstrate explanation style and "
                "natural-language interpretation.\n\n"
                "IMPORTANT:\n"
                "- Do NOT copy its catalogs.\n"
                "- Do NOT copy its schemas.\n"
                "- Do NOT copy its tables.\n"
                "- Do NOT copy its columns.\n"
                "- Do NOT copy its security groups unless independently "
                "present in the current Security Groups list.\n"
                "- Do NOT copy its actions unless independently present in "
                "the current Available Actions list.\n"
                "- The current Data Mesh Structure, Security Groups and "
                "Available Actions always have priority over this example."
            ),
        })

        messages.append({
            "role": "user",
            "content": example["input"]["rule"],
        })

        # ---------------------------------------------------------------
        # IMPORTANT:
        # Do not blindly inject old example action vocabulary.
        # Only provide the example explanation as style reference.
        # ---------------------------------------------------------------

        messages.append({
            "role": "assistant",
            "content": json.dumps(
                example["explanation"],
                indent=2,
            ),
        })

    # -----------------------------------------------------------------------
    # Current rule
    # -----------------------------------------------------------------------

    messages.append({
        "role": "user",
        "content": (
            "Analyze the following NEW client request.\n\n"

            "Rule:\n"
            f"{rule}\n\n"

            "Follow this order:\n"
            "1. Understand what the client wants.\n"
            "2. Identify the security group.\n"
            "3. Identify catalog/schema/table/column if present.\n"
            "4. Infer the intended Trino action from the natural language.\n"
            "5. Check the inferred action against Available Actions.\n"
            "6. Check the resource path against Data Mesh Structure.\n"
            "7. Check the security group against Existing Security Groups.\n"
            "8. Put any corrections in llm_feedback.\n\n"

            "Do not use examples as a source of truth.\n"
            "Use only the authoritative data supplied in the system prompt.\n\n"

            "If the request is valid, llm_feedback MUST be an empty string.\n\n"

            "If the request is invalid, do not simply reject it. "
            "Explain the problem and help the client formulate a valid "
            "request using only valid security groups, resources and actions."
        ),
    })

    # -----------------------------------------------------------------------
    # Call LLM
    # -----------------------------------------------------------------------

    prompt = json.dumps(
        messages,
        indent=2,
    )

    response = llm_call(
        prompt,
        temperature=0.0,
        response_format={
            "type": "json_object"
        },
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
    )

    response = response.strip()

    # -----------------------------------------------------------------------
    # Parse JSON
    # -----------------------------------------------------------------------

    try:

        result = json.loads(
            response
        )

    except json.JSONDecodeError as e:

        raise ValueError(
            f"LLM returned invalid JSON:\n{response}"
        ) from e

    # -----------------------------------------------------------------------
    # Guarantee required fields
    # -----------------------------------------------------------------------

    result.setdefault(
        "text",
        rule,
    )

    result.setdefault(
        "existSecureGroup",
        False,
    )

    result.setdefault(
        "pathExistOnDataMeshStructure",
        False,
    )

    result.setdefault(
        "actionExist",
        False,
    )

    result.setdefault(
        "llm_feedback",
        "",
    )

    return result
