"""
Stage 2 of the pipeline: turn an *extracted* authorization entity
(the JSON produced by `extract_entities` in the extraction script)
into a Rego snippet that follows the exact conventions used in your
reference `trino.authz` policy.

Usage sketch
------------

    from extract_policy import extract_entities          # your stage-1 module
    from rego_policy_generator import (
        generate_rego_policy,
        assemble_full_policy,
    )

    entity = extract_entities(
        client, model, rule, check_for_action, extraction_indexes, security_groups
    )

    snippet = generate_rego_policy(client, model, entity, REFERENCE_POLICY)

    # ... collect one snippet per rule, then:
    full_policy = assemble_full_policy([snippet_1, snippet_2, ...])

NOTE: adjust the `from extract_policy import extract_entities` line above
to match whatever you actually named your stage-1 file.
"""

import json

from Interface.llm_call import llm_call

# ---------------------------------------------------------------------------
# How each Trino operation's `input.action.resource` is shaped.
# This is the Rego-generation equivalent of the "action mapping" that stage 1
# uses -- it removes ambiguity about which resource level (catalog / schema /
# table / column) each operation carries, and whether it's a hard gate
# (raises "Access Denied") or a soft gate (silently filters listings).
# ---------------------------------------------------------------------------
OPERATION_RESOURCE_SHAPES = {
    "ExecuteQuery": "no resource at all - fires before any table/schema is resolved; allow with no resource constraint",
    "AccessCatalog": "hard gate - input.action.resource.catalog.name",
    "FilterCatalogs": "soft gate (SHOW CATALOGS listing) - input.action.resource.catalog.name",
    "ShowSchemas": "hard gate for SHOW SCHEMAS FROM x - input.action.resource.catalog.name (parent level)",
    "FilterSchemas": "soft gate (SHOW SCHEMAS listing) - input.action.resource.schema.catalogName / .schemaName",
    "AccessSchema": "hard gate, needed for USE x.y and any query targeting the schema, also required for information_schema - input.action.resource.schema.catalogName / .schemaName",
    "ShowTables": "hard gate for SHOW TABLES FROM x.y - input.action.resource.schema.catalogName / .schemaName",
    "FilterTables": "soft gate (SHOW TABLES listing) - input.action.resource.table.catalogName / .schemaName",
    "SelectFromColumns": "table-level read check, also fired against information_schema for SHOW/DESCRIBE - input.action.resource.table.catalogName / .schemaName / .tableName",
    "GetColumnMask": "grants permission to query a possibly-masked column; does NOT itself define the mask expression - input.action.resource.table.catalogName / .schemaName / .tableName",
    "GetRowFilters": "grants permission to query possibly row-filtered data; does NOT itself define the filter expression - input.action.resource.table.catalogName / .schemaName / .tableName",
    "InsertIntoTable": "input.action.resource.table.catalogName / .schemaName / .tableName",
    "UpdateTableColumns": "input.action.resource.table.catalogName / .schemaName / .tableName",
    "DeleteFromTable": "input.action.resource.table.catalogName / .schemaName / .tableName",
    "CreateView": "a view is created inside a schema - input.action.resource.schema.catalogName / .schemaName",
}


GENERATE_REGO_SYSTEM_PROMPT_TEMPLATE = """
You are an expert OPA Rego author generating Trino authorization rules.

You will receive, as the user message, a single extracted authorization
policy as JSON with this shape:

{{
  "subject_attribute": "user" | "groups",
  "subject_value": "",
  "resource_type": "catalog" | "schema" | "table" | "column" | "",
  "resource_values": {{
      "catalogName": "",
      "schemaName": "",
      "tableName": "",
      "columnName": ""
  }},
  "trino_action": [] | "*"
}}

Your job is to emit ONLY the new Rego snippet needed to grant that subject
exactly those actions on that resource scope, written to slot into the SAME
policy file as the reference policy below (its `package`, imports,
`default allow := false`, `is_admin`, `is_test`, and the generic `batch`
rules already exist elsewhere in that file -- never redefine them).

How to interpret each Trino operation's resource shape:
{operation_resource_shapes}

STYLE RULES (follow the reference policy's conventions exactly):

1. Define one role-membership helper rule named `is_<subject_value>`
   (lowercase, spaces/hyphens converted to underscores):
   - subject_attribute == "groups" -> `"<subject_value>" in input.context.identity.groups`
   - subject_attribute == "user"   -> `input.context.identity.user == "<subject_value>"`

2. For every action in trino_action, add one `allow if {{ ... }}` block
   gated on `is_<subject_value>`, `input.action.operation == "<Action>"`,
   and the correct resource-path equality checks for that action (see the
   shape reference above). If a `resource_values` field is "*" (or absent),
   OMIT that equality check entirely rather than comparing to the literal
   string "*" -- do not write `== "*"`.

3. When SelectFromColumns, GetColumnMask and GetRowFilters are ALL present
   for the same resource scope, group them into one shared `allow if` block
   using `input.action.operation in {{"SelectFromColumns", "GetColumnMask", "GetRowFilters"}}`,
   exactly like the reference's `analyst_operation` set -- do not write three
   separate blocks for them in that case.

4. If the granted scope is catalog- or schema-level (resource_type is
   "catalog" or "schema", or SelectFromColumns/etc. are requested with a
   wildcard table), also add the supporting navigation allows so metadata
   commands keep working: ShowSchemas/FilterSchemas for the relevant
   catalog, ShowTables/FilterTables for the relevant schema, AccessSchema
   and SelectFromColumns on "information_schema" within that catalog --
   but only add these if AccessCatalog/AccessSchema-level actions were
   actually requested; don't invent navigation access nobody asked for.

5. If trino_action is the string "*" (unrestricted access), emit ONLY
   `allow if is_<subject_value>` with no operation or resource constraints
   at all -- mirror the reference's `is_admin` / `is_test` bypass style.

6. Do not emit `rowFilters`, `columnMask`, or `batchColumnMasks` rules.
   Those encode specific data-masking business logic that is not part of
   the extracted action list, and must be authored separately.

7. Never redefine `default allow := false`, `is_admin`, `is_test`,
   `user_info`, the `batch` rules, or any package/import statement --
   assume all of that already exists in the file this snippet is appended to.

8. Separate each top-level rule (the helper and each `allow if` block) with
   exactly one blank line, matching the reference's formatting, and add a
   short `#` comment above non-obvious blocks (e.g. why a hard gate and a
   soft gate are both needed) the way the reference does.

9. Output RAW REGO ONLY. No markdown fences, no explanation, no repetition
   of the reference policy itself.

Reference policy (style example only -- do not repeat its contents, only
imitate its structure and naming conventions):

{example_rego}
"""


def get_generate_rego_system_prompt(example_rego):
    return GENERATE_REGO_SYSTEM_PROMPT_TEMPLATE.format(
        operation_resource_shapes=json.dumps(OPERATION_RESOURCE_SHAPES, indent=2),
        example_rego=example_rego,
    )

import numpy as np
from Interface.embedding_call import embedding_call


def cosine_similarity(a, b):
    return np.dot(a, b) / (
        np.linalg.norm(a) * np.linalg.norm(b)
    )


def find_best_rego_examples(extracted_entity,example_rego,is_local,n=3,url=None,client=None,embedding_model=None):
    # Turn the extracted entity into text for embedding
    query = json.dumps(extracted_entity, sort_keys=True, indent=2)

    query_embedding = embedding_call(text=query,is_local=is_local,url=url,client=client,embedding_model=embedding_model)

    ranked = sorted(
        example_rego,
        key=lambda ex: cosine_similarity(
            query_embedding,
            ex["embedding"],
        ),
        reverse=True,
    )

    return ranked[:n]


def llm_generate_rego( extracted_entity, example_rego,is_local,  url=None,client=None,model=None):

    prompt=[
            {
                "role": "system",
                "content": get_generate_rego_system_prompt(example_rego),
            },
            {
                "role": "user",
                "content": json.dumps(extracted_entity, indent=2),
            },
        ]

    prompt= json.dumps(prompt,indent=2)

    response=llm_call(prompt, is_local=is_local,url=url, model=model, client=client)

    return response.strip()


def clean_rego_output(raw):
    """Strip an accidental markdown code fence if the model adds one."""

    raw = raw.strip()

    if raw.startswith("```"):
        lines = raw.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        raw = "\n".join(lines).strip()

    return raw


def generate_rego_policy(extracted_entity,example_rego,is_local,url=None,client=None,model=None, embedding_model=None):

    examples = find_best_rego_examples(extracted_entity=extracted_entity,example_rego=example_rego,is_local=is_local,n=3,url=url,client=client,embedding_model=embedding_model)

    # Concatenate the retrieved Rego examples
    example_text = "\n\n".join(
        ex["output"] for ex in examples
    )

    raw = llm_generate_rego(extracted_entity,example_text,is_local,url=url,client=client,model=model)

    print("\n[RAW REGO OUTPUT]\n", raw)

    return clean_rego_output(raw)

# ---------------------------------------------------------------------------
# Boilerplate that is shared by every role and only needs to exist once in
# the final policy file. Pulled verbatim from the reference policy's
# non-role-specific parts.
# ---------------------------------------------------------------------------
BOILERPLATE_HEADER = '''package trino.authz

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false


user_info := resp.body if {
    user := input.context.identity.user

    resp := http.send({
        "method": "GET",
        "url": sprintf("http://ldap-micro-service:5000/users/%s", [user]),
        "raise_error": false
    })

    print("HTTP RESPONSE:", resp)

    resp.status_code == 200
}

############ ROLES ############

is_admin if {
    input.context.identity.user == "trino"
}

is_test if {
    input.context.identity.user == "test_access"
}

############ ALLOW ############

allow if is_admin
allow if is_test'''

BOILERPLATE_FOOTER = '''##################### BATCH #######################
# this assumes the non-batch response field is called "allow"
batch contains i if {
    some i
    raw_resource := input.action.filterResources[i]
    allow with input.action.resource as raw_resource
}

# Corner case: filtering columns is done with a single table item, and many columns inside
# We cannot use our normal logic in other parts of the policy as they are based on sets
# and we need to retain order
batch contains i if {
    some i
    input.action.operation == "FilterColumns"
    count(input.action.filterResources) == 1
    raw_resource := input.action.filterResources[0]
    count(raw_resource["table"]["columns"]) > 0
    new_resources := [
        object.union(raw_resource, {"table": {"column": column_name}})
        | column_name := raw_resource["table"]["columns"][_]
    ]
    allow with input.action.resource as new_resources[i]
}'''


def _split_into_blocks(rego_text):
    """Split a rego snippet into top-level rule blocks on blank lines."""

    blocks = []
    current = []

    for line in rego_text.splitlines():
        if line.strip() == "":
            if current:
                blocks.append("\n".join(current).strip())
                current = []
        else:
            current.append(line)

    if current:
        blocks.append("\n".join(current).strip())

    return blocks


def _block_signature(block):
    """First non-comment line of a block, used as a dedup key."""

    for line in block.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped

    return block


def assemble_full_policy(role_snippets):
    """
    Merge per-role Rego snippets (each produced by `generate_rego_policy`)
    into one complete, loadable policy file, deduplicating any helper rule
    (e.g. `is_analyst if { ... }`) that shows up more than once because the
    same subject appeared in more than one extracted rule.

    Dedup is a best-effort textual match on each block's first line, so it
    only catches exact repeats -- it will NOT merge two different allow
    scopes for the same role into one rule (nor does it need to: Rego
    `allow if` rules are OR'd together regardless of how many there are).
    """

    seen_signatures = set()
    deduped_blocks = []

    for snippet in role_snippets:
        for block in _split_into_blocks(snippet):
            sig = _block_signature(block)
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)
            deduped_blocks.append(block)

    body = "\n\n".join(deduped_blocks)

    return f"{BOILERPLATE_HEADER}\n\n{body}\n\n{BOILERPLATE_FOOTER}\n"

