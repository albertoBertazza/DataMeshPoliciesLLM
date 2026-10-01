import json
import re
import numpy as np
from LLM.Interface.embedding_call import embedding_call
from LLM.Interface.llm_call import llm_call
from Pipelines.costantPath import REWRITTEN_RULE_PATH

# ============================================================================
# Constants
# ============================================================================

RESOURCE_FIELDS = {"catalog", "schema", "table", "column"}

AVAILABLE_ACTION_FIELDS = {"intent", "action"}

EFFECTS = {"allow", "deny"}

# ============================================================================
# Data Mesh traversal
# ============================================================================

def _get_catalogs(data_mesh_structure):
    if not isinstance(data_mesh_structure, dict):
        return []
    catalogs = data_mesh_structure.get("catalogs", [])
    return catalogs if isinstance(catalogs, list) else []

def _find_catalog(data_mesh_structure, catalog_name):
    if not catalog_name:
        return None
    for catalog in _get_catalogs(data_mesh_structure):
        if isinstance(catalog, dict) and catalog.get("name") == catalog_name:
            return catalog
    return None

def _find_schema(catalog, schema_name):
    if not isinstance(catalog, dict) or not schema_name:
        return None
    schemas = catalog.get("schemas", [])
    if not isinstance(schemas, list):
        return None
    for schema in schemas:
        if isinstance(schema, dict) and schema.get("name") == schema_name:
            return schema
    return None

def _find_table(schema, table_name):
    if not isinstance(schema, dict) or not table_name:
        return None
    tables = schema.get("tables", [])
    if not isinstance(tables, list):
        return None
    for table in tables:
        if isinstance(table, dict) and table.get("name") == table_name:
            return table
    return None

def _get_columns(table):
    """
    Return normalized column definitions while preserving the
    authoritative Data Mesh column type.

    Supports both:

        "columns": ["id", "name"]

    and:

        "columns": [
            {"name": "id", "type": "varchar"},
            {"name": "salary", "type": "integer"}
        ]
    """

    if not isinstance(table, dict):
        return []

    columns = table.get("columns", [])
    if not isinstance(columns, list):
        return []

    result = []

    for column in columns:

        # Legacy format:
        # "columns": ["id", "name"]
        if isinstance(column, str):
            if column:
                result.append({ "name": column, "type": "varchar" })
            continue

        # Authoritative Data Mesh format:
        # {"name": "salary", "type": "integer"}
        if isinstance(column, dict):
            name = column.get("name")

            if not isinstance(name, str) or not name:
                continue

            column_type = column.get("type", "varchar")

            if not isinstance(column_type, str) or not column_type.strip():
                column_type = "varchar"

            result.append({ "name": name, "type": column_type.strip() })

    return result

def _get_schema_names(catalog):
    if not isinstance(catalog, dict):
        return []
    result = []
    for schema in catalog.get("schemas", []):
        if not isinstance(schema, dict):
            continue
        name = schema.get("name")
        if isinstance(name, str) and name:
            result.append(name)
    return result

def _get_table_names(schema):
    if not isinstance(schema, dict):
        return []
    result = []
    for table in schema.get("tables", []):
        if not isinstance(table, dict):
            continue
        name = table.get("name")
        if isinstance(name, str) and name:
            result.append(name)
    return result

def _get_column_names(table):
    return [ column["name"] for column in _get_columns(table) if isinstance(column, dict) and column.get("name") ]

def _get_column_type(table, column_name):
    """
    Return the authoritative Data Mesh type for a column.
    """

    if not isinstance(column_name, str) or not column_name:
        return None

    for column in _get_columns(table):
        if column.get("name") == column_name:
            return column.get("type", "varchar")

    return None

def _find_column_definition( data_mesh_structure, catalog_name, schema_name, table_name, column_name ):
    """
    Resolve the complete Data Mesh column definition.
    """

    catalog = _find_catalog( data_mesh_structure, catalog_name )

    if catalog is None:
        return None

    schema = _find_schema( catalog, schema_name )

    if schema is None:
        return None

    table = _find_table( schema, table_name )

    if table is None:
        return None

    for column in _get_columns(table):
        if column.get("name") == column_name:
            return column

    return None

# ============================================================================
# Normalize Data Mesh
# ============================================================================

def _normalize_data_mesh_structure(data_mesh_structure):
    """
    Supports both:

        {
            "iceberg": {
                "hr": {
                    "employees": ["id", "name"]
                }
            }
        }

    and:

        {
            "catalogs": [
                {
                    "name": "iceberg",
                    "schemas": [...]
                }
            ]
        }
    """

    if not isinstance(data_mesh_structure, dict):
        return {"catalogs": []}
    if isinstance(data_mesh_structure.get("catalogs"), list):
        return data_mesh_structure
    catalogs = []
    for catalog_name, schemas_data in data_mesh_structure.items():
        if not isinstance(schemas_data, dict):
            continue
        schemas = []
        for schema_name, tables_data in schemas_data.items():
            if not isinstance(tables_data, dict):
                continue
            tables = []
            for table_name, columns_data in tables_data.items():
                columns = []
                if isinstance(columns_data, list):
                    for column in columns_data:
                        if isinstance(column, str):
                            columns.append(column)
                        elif isinstance(column, dict):
                            column_name = column.get("name")

                            if column_name:
                                columns.append({ "name": column_name, "type": column.get("type", "varchar") })

                tables.append({ "name": table_name, "columns": columns })
            schemas.append({ "name": schema_name, "tables": tables })
        catalogs.append({ "name": catalog_name, "schemas": schemas })
    return {"catalogs": catalogs}

# ============================================================================
# Catalog inference
# ============================================================================

def _infer_unique_catalog(data_mesh_structure, schema_name):
    if not schema_name:
        return None
    matches = []
    for catalog in _get_catalogs(data_mesh_structure):
        if not isinstance(catalog, dict):
            continue
        if _find_schema(catalog, schema_name) is not None:
            catalog_name = catalog.get("name")
            if catalog_name:
                matches.append(catalog_name)
    return matches[0] if len(matches) == 1 else None

# ============================================================================
# Resource validation
# ============================================================================

def _validate_resource_path(resource, data_mesh_structure):
    if not isinstance(resource, dict):
        return { "valid": False, "feedback": "The extracted resource is not a valid object." }
    # Normalize values.
    for field in RESOURCE_FIELDS:
        value = resource.get(field)
        if isinstance(value, str):
            value = value.strip()
            resource[field] = value if value else None
        elif value is not None:
            return { "valid": False, "feedback": f"Resource field '{field}' must be a string or null." }

    catalog_name = resource.get("catalog")
    schema_name = resource.get("schema")
    table_name = resource.get("table")
    column_name = resource.get("column")
    # No resource specified.
    if not any( [catalog_name, schema_name, table_name, column_name] ):
        return { "valid": True, "feedback": "" }
    # Hierarchy constraints.
    if column_name and not table_name:
        return { "valid": False, "feedback": ( f"The column '{column_name}' was specified without a table." ) }
    if table_name and not schema_name:
        return { "valid": False, "feedback": ( f"The table '{table_name}' was specified without a schema." ) }
    # Infer catalog from schema only when unique.
    if catalog_name is None and schema_name:
        inferred_catalog = _infer_unique_catalog( data_mesh_structure, schema_name )
        if inferred_catalog:
            resource["catalog"] = inferred_catalog
            catalog_name = inferred_catalog
        else:
            matching_catalogs = []
            for catalog in _get_catalogs(data_mesh_structure):
                if not isinstance(catalog, dict):
                    continue
                if _find_schema(catalog, schema_name) is not None:
                    name = catalog.get("name")
                    if name:
                        matching_catalogs.append(name)
            if len(matching_catalogs) > 1:
                return { "valid": False, "feedback": ( f"The schema '{schema_name}' exists in multiple " f"catalogs: " + ", ".join(repr(x) for x in matching_catalogs) + ". A catalog must be specified." ) }
            return { "valid": False, "feedback": ( f"The schema '{schema_name}' could not be resolved " f"to a unique catalog." ) }
    if not catalog_name:
        return { "valid": False, "feedback": ( "The request contains a resource but no catalog " "could be identified." ) }
    # Catalog.
    catalog = _find_catalog( data_mesh_structure, catalog_name )
    if catalog is None:
        available = [ item.get("name") for item in _get_catalogs(data_mesh_structure) if isinstance(item, dict) and item.get("name") ]
        return { "valid": False, "feedback": ( f"The catalog '{catalog_name}' does not exist. " "Available catalogs are: " + (", ".join(repr(x) for x in available) if available else "none") + "." ) }
    # Catalog-only.
    if not schema_name:
        return { "valid": True, "feedback": "" }

    # Schema.
    schema = _find_schema( catalog, schema_name )
    if schema is None:
        available = _get_schema_names(catalog)
        return { "valid": False, "feedback": ( f"The schema '{schema_name}' does not exist " f"in catalog '{catalog_name}'. " "Available schemas are: " + (", ".join(repr(x) for x in available) if available else "none") + "." ) }

    # IMPORTANT:
    # Schema-only authorization is valid.
    if not table_name:
        return { "valid": True, "feedback": "" }
    # Table.
    table = _find_table( schema, table_name )
    if table is None:
        available = _get_table_names(schema)
        return {
            "valid": False,
            "feedback": ( f"The table '{table_name}' does not exist " f"in catalog '{catalog_name}', " f"schema '{schema_name}'. " "Available tables are: " + (", ".join(repr(x) for x in available) if available else "none") + "." )
        }
    # Table-only.
    if not column_name:
        return { "valid": True, "feedback": "" }
    # Column.
    column_names = _get_column_names(table)
    if column_name not in column_names:
        return {
            "valid": False,
            "feedback": (
                f"The column '{column_name}' does not exist "
                f"in catalog '{catalog_name}', "
                f"schema '{schema_name}', "
                f"table '{table_name}'. "
                "Available columns are: "
                + ( ", ".join(repr(x) for x in column_names) if column_names else "none" )
                + "."
            )
        }
    return { "valid": True, "feedback": "" }

# ============================================================================
# Resource expansion
# ============================================================================

def _make_expanded_resource( catalog_name, schema_name, table_name, column_name="" ):
    return { "catalogName": catalog_name, "schemaName": schema_name, "tableName": table_name, "columnName": column_name }

def _expand_table(catalog_name, schema_name, table):
    if not isinstance(table, dict):
        return []
    table_name = table.get("name")
    if not table_name:
        return []
    return [ _make_expanded_resource( catalog_name, schema_name, table_name ) ]

def _expand_schema(catalog_name, schema_name, schema):
    if not isinstance(schema, dict):
        return []
    result = []
    for table in schema.get("tables", []):
        result.extend( _expand_table( catalog_name, schema_name, table ) )
    return result

def _expand_catalog(catalog_name, catalog):
    if not isinstance(catalog, dict):
        return []
    result = []
    for schema in catalog.get("schemas", []):
        if not isinstance(schema, dict):
            continue
        schema_name = schema.get("name")
        if not schema_name:
            continue
        result.extend( _expand_schema( catalog_name, schema_name, schema ) )
    return result

def _expand_resource(resource, data_mesh_structure):
    if not isinstance(resource, dict):
        return []
    catalog_name = resource.get("catalog")
    schema_name = resource.get("schema")
    table_name = resource.get("table")
    column_name = resource.get("column")
    if not catalog_name:
        return []
    catalog = _find_catalog( data_mesh_structure, catalog_name )
    if catalog is None:
        return []
    # Catalog scope.
    if not schema_name:
        return _expand_catalog( catalog_name, catalog )
    schema = _find_schema( catalog, schema_name )
    if schema is None:
        return []
    # Schema scope.
    if not table_name:
        return _expand_schema( catalog_name, schema_name, schema )
    table = _find_table( schema, table_name )
    if table is None:
        return []
    # Table scope.
    if not column_name:
        return [ _make_expanded_resource( catalog_name, schema_name, table_name ) ]
    # Column scope.
    if column_name not in _get_column_names(table):
        return []
    return [ _make_expanded_resource( catalog_name, schema_name, table_name, column_name ) ]

# ============================================================================
# Similarity
# ============================================================================

def cosine_similarity(a, b):
    denominator = ( np.linalg.norm(a) * np.linalg.norm(b) )
    if denominator == 0:
        return 0.0
    return float( np.dot(a, b) / denominator )

def find_best_examples( rule, index, is_local, n=3, embedding_url=None, client=None, embedding_model=None ):
    if not index:
        return []
    query_embedding = embedding_call( text=rule, is_local=is_local, embedding_url=embedding_url, client=client, embedding_model=embedding_model )
    ranked = []
    for example in index:
        if not isinstance(example, dict):
            continue
        embedding = example.get("embedding")
        if embedding is None:
            continue
        ranked.append( ( cosine_similarity( query_embedding, embedding ), example ) )
    ranked.sort( key=lambda item: item[0], reverse=True )
    return [ example for _, example in ranked[:n] ]

# ============================================================================
# Action helpers
# ============================================================================

def _normalize_available_actions(available_actions):
    if not isinstance(available_actions, list):
        return []
    result = []
    for action in available_actions:
        if isinstance(action, str):
            action = action.strip()
            if action and action not in result:
                result.append(action)
    return result

def _normalize_extracted_actions( requested_actions, available_actions):
    """
    Normalize common LLM action-extraction mistakes.

    The LLM may:
    - return the canonical action directly;
    - put the canonical action name into `intent`;
    - leave `action` as null;
    - return a natural-language intent containing additional
      resource/context information.

    Examples:

        "update table"
            -> UpdateTableAction

        "update table in schema finance"
            -> UpdateTableAction

        "select from table inside finance"
            -> SelectFromTableAction

        "delete rows from table in finance"
            -> DeleteFromTableAction

        "drop table in schema finance"
            -> DropTableAction

    The complete natural-language intent is preserved.
    """
    available = set(available_actions)

    # ------------------------------------------------------------------
    # Exact natural-language mappings
    # ------------------------------------------------------------------
    exact_mappings = {
        # SELECT
        "select": "SelectFromTableAction",
        "select from table": "SelectFromTableAction",
        "select from a table": "SelectFromTableAction",
        "read": "SelectFromTableAction",
        "read table": "SelectFromTableAction",
        "read from table": "SelectFromTableAction",
        "query": "SelectFromTableAction",
        "query table": "SelectFromTableAction",

        # INSERT
        "insert": "InsertIntoTableAction",
        "insert into table": "InsertIntoTableAction",
        "insert into a table": "InsertIntoTableAction",
        "insert data into table": "InsertIntoTableAction",
        "insert rows": "InsertIntoTableAction",
        "add rows to table": "InsertIntoTableAction",

        # UPDATE
        "update": "UpdateTableAction",
        "update table": "UpdateTableAction",
        "update a table": "UpdateTableAction",
        "update rows": "UpdateTableAction",
        "update table columns": "UpdateTableAction",
        "modify table data": "UpdateTableAction",
        "modify rows in table": "UpdateTableAction",

        # DELETE ROWS
        "delete": "DeleteFromTableAction",
        "delete rows": "DeleteFromTableAction",
        "delete rows from table": "DeleteFromTableAction",
        "delete table rows": "DeleteFromTableAction",
        "remove rows from table": "DeleteFromTableAction",
        "remove rows": "DeleteFromTableAction",

        # TRUNCATE
        "truncate": "TruncateTableAction",
        "truncate table": "TruncateTableAction",
        "truncate a table": "TruncateTableAction",
        "empty table": "TruncateTableAction",
        "clear table": "TruncateTableAction",
        "remove all rows from table": "TruncateTableAction",
        "delete all rows from table": "TruncateTableAction",

        # CREATE
        "create table": "CreateTableAction",
        "create a table": "CreateTableAction",
        "creating table": "CreateTableAction",
        "make a table": "CreateTableAction",

        "create schema": "CreateSchemaAction",
        "create a schema": "CreateSchemaAction",
        "creating schema": "CreateSchemaAction",
        "make a schema": "CreateSchemaAction",

        "create view": "CreateViewAction",
        "create a view": "CreateViewAction",
        "creating view": "CreateViewAction",
        "make a view": "CreateViewAction",

        "create materialized view": "CreateMaterializedViewAction",
        "create a materialized view": "CreateMaterializedViewAction",
        "creating materialized view": "CreateMaterializedViewAction",
        "make a materialized view": "CreateMaterializedViewAction",

        # DROP
        "drop table": "DropTableAction",
        "drop a table": "DropTableAction",
        "delete table": "DropTableAction",
        "delete a table": "DropTableAction",
        "remove table": "DropTableAction",
        "remove a table": "DropTableAction",

        "drop view": "DropViewAction",
        "drop a view": "DropViewAction",
        "delete view": "DropViewAction",
        "delete a view": "DropViewAction",
        "remove view": "DropViewAction",

        "drop materialized view": "DropMaterializedViewAction",
        "drop a materialized view": "DropMaterializedViewAction",
        "delete materialized view": "DropMaterializedViewAction",
        "delete a materialized view": "DropMaterializedViewAction",
        "remove materialized view": "DropMaterializedViewAction",

        "drop schema": "DropSchemaAction",
        "drop a schema": "DropSchemaAction",
        "delete schema": "DropSchemaAction",
        "delete a schema": "DropSchemaAction",
        "remove schema": "DropSchemaAction",

        # COLUMNS
        "add column": "AddColumnAction",
        "add a column": "AddColumnAction",
        "adding column": "AddColumnAction",

        "drop column": "DropColumnAction",
        "drop a column": "DropColumnAction",
        "delete column": "DropColumnAction",
        "delete a column": "DropColumnAction",
        "remove column": "DropColumnAction",
        "remove a column": "DropColumnAction",

        "rename column": "RenameColumnAction",
        "rename a column": "RenameColumnAction",
        "change column name": "RenameColumnAction",

        # RENAME TABLE
        "rename table": "RenameTableAction",
        "rename a table": "RenameTableAction",
        "change table name": "RenameTableAction",

        # RENAME VIEW
        "rename view": "RenameViewAction",
        "rename a view": "RenameViewAction",
        "change view name": "RenameViewAction",

        # RENAME MATERIALIZED VIEW
        "rename materialized view": "RenameMaterializedViewAction",
        "rename a materialized view": "RenameMaterializedViewAction",
        "change materialized view name": "RenameMaterializedViewAction",

        # MATERIALIZED VIEW
        "refresh materialized view": "RefreshMaterializedViewAction",
        "refresh a materialized view": "RefreshMaterializedViewAction",
        "refresh materialized views": "RefreshMaterializedViewAction",

        # TABLE COMMENTS
        "add comment to table": "SetTableCommentAction",
        "set comment on table": "SetTableCommentAction",
        "set table comment": "SetTableCommentAction",
        "comment on table": "SetTableCommentAction",

        # COLUMN COMMENTS
        "add comment to column": "SetColumnCommentAction",
        "set comment on column": "SetColumnCommentAction",
        "set column comment": "SetColumnCommentAction",
        "comment on column": "SetColumnCommentAction",

        # VIEW COMMENTS
        "add comment to view": "SetViewCommentAction",
        "set comment on view": "SetViewCommentAction",
        "set view comment": "SetViewCommentAction",
        "comment on view": "SetViewCommentAction",

        # SHOW TABLES
        "show tables": "ShowTablesAction",
        "show table": "ShowTablesAction",
        "list tables": "ShowTablesAction",
        "list table": "ShowTablesAction",
        "show available tables": "ShowTablesAction",
        "list available tables": "ShowTablesAction",

        # SHOW SCHEMAS
        "show schemas": "ShowSchemasAction",
        "show schema": "ShowSchemasAction",
        "list schemas": "ShowSchemasAction",
        "list schema": "ShowSchemasAction",
        "show available schemas": "ShowSchemasAction",
        "list available schemas": "ShowSchemasAction",

        # SHOW COLUMNS
        "show columns": "ShowColumnsAction",
        "show table columns": "ShowColumnsAction",
        "list columns": "ShowColumnsAction",
        "list table columns": "ShowColumnsAction",
        "view columns": "ShowColumnsAction",

        # SHOW CREATE TABLE
        "show create table": "ShowCreateTableAction",
        "show table definition": "ShowCreateTableAction",
        "show table ddl": "ShowCreateTableAction",
        "get table definition": "ShowCreateTableAction",

        # SHOW CREATE SCHEMA
        "show create schema": "ShowCreateSchemaAction",
        "show schema definition": "ShowCreateSchemaAction",
        "show schema ddl": "ShowCreateSchemaAction",
        "get schema definition": "ShowCreateSchemaAction",
    }

    # ------------------------------------------------------------------
    # Context-aware mappings.
    #
    # These are checked as phrases contained in the intent, allowing:
    #
    #   "update table in schema finance"
    #   "update a table inside finance"
    #   "select from table inside hr"
    #
    # The longest phrases are checked first.
    # ------------------------------------------------------------------
    contains_mappings = sorted( exact_mappings.items(), key=lambda item: len(item[0]), reverse=True)
    normalized = []
    for item in requested_actions:
        if not isinstance(item, dict):
            continue
        intent = str( item.get("intent", "") ).strip()
        action = item.get("action")
        effect = item.get( "effect", "allow")
        normalized_intent = re.sub( r"\s+", " ", intent.lower().strip())

        # --------------------------------------------------------------
        # 1. If LLM already returned a valid canonical action,
        #    ALWAYS preserve it.
        # --------------------------------------------------------------
        if action in available:
            normalized.append( { "intent": intent, "action": action, "effect": effect} )
            continue

        # --------------------------------------------------------------
        # 2. Sometimes the LLM puts the canonical action in `intent`.
        # --------------------------------------------------------------
        if ( action is None and intent in available ):
            action = intent

        # --------------------------------------------------------------
        # 3. Exact natural-language mapping.
        # --------------------------------------------------------------
        if action is None:
            action = exact_mappings.get( normalized_intent )

        # --------------------------------------------------------------
        # 4. Contained phrase mapping.
        #
        # Example:
        #
        # "update table in schema finance"
        #
        # contains:
        #
        # "update table"
        #
        # therefore:
        #
        # UpdateTableAction
        # --------------------------------------------------------------
        if action is None:
            for phrase, mapped_action in contains_mappings:
                if phrase not in normalized_intent:
                    continue
                if mapped_action in available:
                    action = mapped_action
                    break
        normalized.append( { "intent": intent, "action": action, "effect": effect} )
    return normalized

def _validate_actions(requested_actions, available_actions):
    """
    Validate ordinary Trino actions.

    An empty action list is valid because a rule may contain only
    a column mask or row filter. Those effects are validated
    separately by _validate_effects().
    """

    if not isinstance(requested_actions, list):
        return { "valid": False, "feedback": "The extracted actions are not a valid list." }

    available = set(available_actions)
    invalid = []
    valid = []

    for item in requested_actions:
        if not isinstance(item, dict):
            invalid.append({ "intent": "", "action": None })
            continue

        intent = item.get("intent", "")
        action = item.get("action")

        if action is None:
            invalid.append({ "intent": intent, "action": None })
            continue

        if action not in available:
            invalid.append({ "intent": intent, "action": action })
            continue

        valid.append(action)

    if invalid:
        messages = []

        for item in invalid:
            if item["action"] is None:
                messages.append( f"The requested operation '{item['intent']}' " "could not be mapped to any available action." )
            else:
                messages.append( f"The inferred action '{item['action']}' " "is not in the available actions." )

        messages.append( "Available actions are: " + ( ", ".join(available_actions) if available_actions else "none" ) + "." )

        return { "valid": False, "feedback": " ".join(messages) }

    # Empty is valid: the rule may contain only a mask/filter.
    return { "valid": True, "feedback": "" }

# ============================================================================
# JSON helpers
# ============================================================================

def _clean_json_response(response):
    if response is None:
        raise ValueError("LLM returned no response.")
    response = str(response).strip()
    if not response:
        raise ValueError("LLM returned an empty response.")
    if response.startswith("```"):
        lines = response.splitlines()
        response = "\n".join( line for line in lines if not line.strip().startswith("```") ).strip()
    start = response.find("{")
    if start < 0:
        raise ValueError( "LLM response does not contain a JSON object:\n" + response )
    end = response.rfind("}")
    if end < start:
        raise ValueError( "LLM response contains an incomplete JSON object:\n" + response )
    return response[start:end + 1].strip()

def _llm_json( system_prompt, user_prompt, is_local, chat_url=None, client=None, model=None ):
    system_content = ( "You must return the answer as valid JSON. " "The response must be a JSON object only.\n\n" + system_prompt.strip() )
    messages = [ { "role": "system", "content": system_content }, { "role": "user", "content": user_prompt.strip() } ]
    response = llm_call( messages=messages, temperature=0.0, response_format={"type": "json_object"}, max_tokens=1200, is_local=is_local, chat_url=chat_url, client=client, model=model )
    response = _clean_json_response(response)
    try:
        result = json.loads(response)
    except json.JSONDecodeError as e:
        raise ValueError( "LLM returned invalid JSON:\n" + response ) from e
    if not isinstance(result, dict):
        raise ValueError( "LLM JSON response must be an object:\n" + json.dumps( result, ensure_ascii=False, indent=2 ) )
    return result

# ============================================================================
# Security group extraction
# ============================================================================

def _extract_security_group( rule, security_groups, is_local, chat_url=None, client=None, model=None ):

    system_prompt = """
Extract the security group or role explicitly mentioned
in the authorization rule.

Return ONLY:

{
  "security_group": null
}

Rules:

1. Extract only an explicitly mentioned security group.
2. Do not invent a group.
3. Do not infer a group from the resource.
4. Do not infer a group from the action.
5. Python validates whether the group exists.
6. Preserve the group name.
7. If no group is mentioned, return null.
8. Return no other fields.
"""

    result = _llm_json( system_prompt, ( "Available security groups:\n" + json.dumps( security_groups, ensure_ascii=False, indent=2 ) + "\n\nRule:\n" + rule ), is_local=is_local, chat_url=chat_url, client=client, model=model )
    if set(result.keys()) != {"security_group"}:
        raise ValueError( "Security group extraction returned invalid JSON." )
    group = result.get("security_group")
    if group is None or group == "":
        return { "security_group": None, "existSecureGroup": False, "feedback": ( "No security group could be identified " "in the request." ) }
    if not isinstance(group, str):
        raise ValueError( "'security_group' must be a string or null." )
    group = group.strip()
    if group in security_groups:
        return { "security_group": group, "existSecureGroup": True, "feedback": "" }
    return {
        "security_group": group,
        "existSecureGroup": False,
        "feedback": ( f"The security group '{group}' does not exist. " "Available security groups are: " + ( ", ".join(repr(x) for x in security_groups) if security_groups else "none" ) + "." )
    }

# ============================================================================
# Resource extraction
# ============================================================================

def _extract_resource( rule, data_mesh_structure, is_local, chat_url=None, client=None, model=None ):
    system_prompt = """
Extract ONLY the DATA RESOURCE explicitly mentioned.

Hierarchy:

catalog
  -> schema
      -> table
          -> column

Return ONLY:

{
  "catalog": null,
  "schema": null,
  "table": null,
  "column": null
}

Rules:

1. Extract only explicitly mentioned resource names.
2. Never invent a resource.
3. Never replace one resource with another.
4. Python validates existence.
5. Preserve names exactly.
6. Missing levels must be null.
7. Schema without table means table=null.
8. Catalog without schema means schema=null.
9. Table requires schema.
10. Column requires table.
11. A rule about "tables inside schema X" is schema-level.
12. Do NOT choose an arbitrary table when the rule is schema-level.
13. Return no other fields.

Examples:

"hr_manager cannot select from tables in schema hr"

{
  "catalog": null,
  "schema": "hr",
  "table": null,
  "column": null
}

"hr_manager cannot select from employees in schema hr"

{
  "catalog": null,
  "schema": "hr",
  "table": "employees",
  "column": null
}

"hr_manager cannot select salary from employees in schema hr"

{
  "catalog": null,
  "schema": "hr",
  "table": "employees",
  "column": "salary"
}
"""

    result = _llm_json( system_prompt, ( "Data Mesh Structure:\n" + json.dumps( data_mesh_structure, ensure_ascii=False, indent=2 ) + "\n\nRule:\n" + rule ), is_local=is_local, chat_url=chat_url, client=client, model=model )
    if set(result.keys()) != RESOURCE_FIELDS:
        raise ValueError( "Resource extraction returned invalid JSON. " f"Received: {json.dumps(result, ensure_ascii=False)}" )
    resource = { field: result.get(field) for field in RESOURCE_FIELDS }
    for field, value in resource.items():
        if value is not None and not isinstance(value, str):
            raise ValueError( f"Resource field '{field}' must be " "a string or null." )
        if isinstance(value, str):
            value = value.strip()
            resource[field] = value if value else None

    # ------------------------------------------------------------------------
    # Deterministic table recovery.
    #
    # IMPORTANT:
    # Only recover a table if the rule explicitly contains exactly one
    # existing table name. Never recover a table merely because a schema
    # contains tables.
    # ------------------------------------------------------------------------
    if ( resource["table"] is None and resource["schema"] is not None and resource["catalog"] is not None ):
        catalog = _find_catalog( data_mesh_structure, resource["catalog"] )
        schema = _find_schema( catalog, resource["schema"] )
        if schema is not None:
            candidate_tables = []
            rule_lower = rule.lower()
            for table_name in _get_table_names(schema):
                pattern = ( r"\b" + re.escape(table_name.lower()) + r"\b" )
                if re.search(pattern, rule_lower):
                    candidate_tables.append(table_name)
            if len(candidate_tables) == 1:
                resource["table"] = candidate_tables[0]
            elif len(candidate_tables) > 1:
                raise ValueError( "Multiple table names were explicitly identified " "but the resource extractor did not return a table: " + ", ".join( repr(x) for x in candidate_tables ) )
    return resource

# ============================================================================
# Column mask / row filter extraction
# ============================================================================

def _extract_effects( rule, resource, data_mesh_structure, is_local, chat_url=None, client=None, model=None ):
    """
    Extract optional row-filter and column-mask declarations.

    Column masks are type-sensitive.

    A mask expression MUST return the same SQL type as the
    Data Mesh column.

    Example:

        annual_salary -> integer

        valid:
            0
            999999
            CAST(0 AS integer)

        invalid:
            '****'
            'hidden'

    Return:

    {
        "row_filter": null,
        "column_masks": {}
    }
    """

    # ---------------------------------------------------------
    # Resolve authoritative column type
    # ---------------------------------------------------------

    resource_column = resource.get("column")

    column_type = None

    if ( resource.get("catalog") and resource.get("schema") and resource.get("table") and resource_column ):
        column_definition = _find_column_definition( data_mesh_structure=data_mesh_structure, catalog_name=resource["catalog"], schema_name=resource["schema"], table_name=resource["table"], column_name=resource_column )

        if column_definition is not None:
            column_type = column_definition.get("type")

    # ---------------------------------------------------------
    # LLM prompt
    # ---------------------------------------------------------

    system_prompt = f"""
    Extract optional DATA FILTERING declarations from a Trino
    authorization rule.

    Return ONLY:

    {{
      "row_filter": null,
      "column_masks": {{}}
    }}

    Rules:

    1. A column mask transforms, masks, hides, replaces, or otherwise
       changes the VALUE returned for a specific column.

    2. A row filter restricts WHICH ROWS are visible using a SQL
       predicate.

    3. Do not invent expressions.

    4. Preserve the SQL expression stated by the user whenever it
       is already type-compatible.

    5. A column mask MUST return the SAME SQL TYPE as the column
       being masked.

    6. The authoritative Data Mesh column type is:

       column = {resource_column or "none"}
       type   = {column_type or "unknown"}

    7. NEVER return a varchar/string expression for an integer,
       bigint, smallint, tinyint, decimal, real, double, boolean,
       date, timestamp, or other non-varchar column.

    8. Examples:

       INTEGER column:
           valid:
               0
               999
               CAST(0 AS integer)

           invalid:
               '****'
               'hidden'

       BIGINT column:
           valid:
               0
               CAST(0 AS bigint)

       DOUBLE column:
           valid:
               0.0
               CAST(0.0 AS double)

       DECIMAL column:
           valid:
               CAST(0 AS decimal(18,2))

       BOOLEAN column:
           valid:
               false
               true

       VARCHAR column:
           valid:
               '****'
               'hidden'

    9. If the user's requested mask is incompatible with the
       authoritative column type, convert it to a simple
       type-compatible masking expression.

       For example:

           Rule:
           "mask annual_salary as '****'"

           Data Mesh:
           annual_salary -> integer

           Return:

           {{
             "row_filter": null,
             "column_masks": {{
               "annual_salary": "0"
             }}
           }}

    10. A column mask requires a specific column.

    11. The key of "column_masks" MUST be the actual column name.

    12. A row filter does not change column values.

    13. Do not interpret a column mask as an ordinary Trino action.

    14. If there is no row filter, return:
        "row_filter": null

    15. If there are no column masks, return:
        "column_masks": {{}}

    16. A row filter must be a SQL predicate compatible with the
        columns referenced by the Data Mesh.

    Examples:

    Rule:
    "mask email as '****' || substring(email, -4)"

    If email is varchar:

    {{
      "row_filter": null,
      "column_masks": {{
        "email": "'****' || substring(email, -4)"
      }}
    }}

    Rule:
    "mask salary as '****'"

    If salary is integer:

    {{
      "row_filter": null,
      "column_masks": {{
        "salary": "0"
      }}
    }}

    Rule:
    "only show rows where department = 'HR'"

    {{
      "row_filter": "department = 'HR'",
      "column_masks": {{}}
    }}

    Rule:
    "show employees where department = 'HR' and mask email as
    '****' || substring(email, -4)"

    {{
      "row_filter": "department = 'HR'",
      "column_masks": {{
        "email": "'****' || substring(email, -4)"
      }}
    }}
    """
    context = { "rule": rule, "resource": resource, "column_type": column_type }
    result = _llm_json( system_prompt, json.dumps( context, ensure_ascii=False, indent=2 ), is_local=is_local, chat_url=chat_url, client=client, model=model )
    if set(result.keys()) != { "row_filter", "column_masks" }:
        raise ValueError( "Column/row effect extraction returned invalid JSON. " f"Received: {json.dumps(result, ensure_ascii=False)}" )
    row_filter = result.get("row_filter")
    column_masks = result.get("column_masks")
    if row_filter is not None and not isinstance(row_filter, str):
        raise ValueError( "'row_filter' must be a string or null." )
    if not isinstance(column_masks, dict):
        raise ValueError( "'column_masks' must be an object." )
    normalized_masks = {}
    for column, expression in column_masks.items():
        if not isinstance(column, str) or not column.strip():
            raise ValueError( "Column mask keys must be non-empty column names." )
        if not isinstance(expression, str) or not expression.strip():
            raise ValueError( f"Column mask for '{column}' " "must be a non-empty string." )
        normalized_masks[column.strip()] = expression.strip()
    return { "row_filter": ( row_filter.strip() if isinstance(row_filter, str) and row_filter.strip() else None ), "column_masks": normalized_masks }

def _validate_effects( effects, resource, data_mesh_structure ):
    """
    Validate row-filter and column-mask scope against the
    authoritative Data Mesh.
    """
    feedback = []
    row_filter = effects.get("row_filter")
    column_masks = effects.get("column_masks", {})
    if not isinstance(column_masks, dict):
        feedback.append( "'column_masks' must be an object." )
        column_masks = {}

    # ---------------------------------------------------------
    # Column masks
    # ---------------------------------------------------------
    if column_masks:
        resource_column = resource.get("column")
        if not resource_column:
            feedback.append( "A column mask requires a specific resource column." )
        else:
            # The resource column must correspond to the mask.
            if resource_column not in column_masks:
                feedback.append( "The column mask must target the resource column " f"'{resource_column}'." )
        # Validate every mask column against the Data Mesh.
        table = resource.get("table")
        schema = resource.get("schema")
        catalog = resource.get("catalog")
        if catalog and schema and table:
            catalog_obj = _find_catalog( data_mesh_structure, catalog )
            schema_obj = _find_schema( catalog_obj, schema )
            table_obj = _find_table( schema_obj, table )
            if table_obj is not None:
                valid_columns = set( _get_column_names(table_obj) )
                for column in column_masks:
                    if column not in valid_columns:
                        feedback.append( f"The column mask references unknown " f"column '{column}'." )

    # ---------------------------------------------------------
    # Row filter
    # ---------------------------------------------------------
    if row_filter and not resource.get("table"):
        feedback.append( "A row filter requires a specific table." )

    # ---------------------------------------------------------
    # Resource validity
    # ---------------------------------------------------------
    path_result = _validate_resource_path( resource, data_mesh_structure )
    if not path_result["valid"]:
        feedback.append(path_result["feedback"])
    return { "valid": not feedback, "feedback": " ".join(feedback) }

# ============================================================================
# Action extraction
# ============================================================================

def _format_action_examples(examples):
    blocks = []
    for ex in examples or []:
        if not isinstance(ex, dict):
            continue
        rule = (ex.get("input") or {}).get("rule")
        exp = ex.get("explanation") or {}
        if not rule:
            continue
        items = ( [ { "intent": a, "action": a, "effect": "allow" } for a in exp.get("allowed", []) ] + [ { "intent": a, "action": a, "effect": "deny" } for a in exp.get("deny", []) ] )
        blocks.append( "Rule:\n" + rule + "\nReturn:\n" + json.dumps( { "requested_actions": items }, ensure_ascii=False ) )
    return ( "\n\n".join(blocks) if blocks else "No examples." )

def _extract_actions( rule, available_actions, is_local, chat_url=None, client=None, model=None, examples=None ):
    """
    Extract ordinary Trino authorization operations.

    IMPORTANT:
    Column masks and row filters are NOT actions. If the rule only
    describes a column mask or row filter, return an empty
    requested_actions list.

    Examples:

        "auditor has applied a filter on column price ..."
            -> []

        "auditor masks price as '$$$' ..."
            -> []

        "auditor can select from table X but masks price ..."
            -> SelectFromTableAction

    A masking/filtering operation must never be converted into
    UpdateTableAction.
    """

    system_prompt = """
    Identify the intended Trino authorization operations and whether
    each operation is allowed or denied.

    Return ONLY:

    {
      "requested_actions": [
        {
          "intent": "",
          "action": null,
          "effect": "allow"
        }
      ]
    }

    Rules:

    1. "intent" MUST describe an ordinary authorization operation
       in natural language.

    2. "action" MUST contain the exact matching action name from
       Available Actions.

    3. NEVER interpret a column mask as UpdateTableAction.

    4. NEVER interpret a row filter as an update, delete, select,
       or other ordinary action.

    5. Column masks and row filters are handled separately by Python.
       They are NOT Trino actions.

    6. If the rule ONLY describes a column mask or row filter,
       return:

       {
         "requested_actions": []
       }

    7. A column mask is language such as:
       - mask a column
       - masked column
       - replace column values
       - replace values in a column
       - hide column values
       - transform column values
       - show $$$ instead of the value
       - apply a mask
       - applied a filter on column X where the intention is to
         replace/mask the displayed column value

    8. A row filter is language such as:
       - filter rows
       - restrict rows
       - only show rows where ...
       - rows where ...
       - apply a row filter
       - restrict access to rows

    9. IMPORTANT:
       "update column values" normally means UpdateTableAction ONLY
       when the user actually requests a database update operation.

       For example:

       "auditor can update the price column"
           -> UpdateTableAction

       But:

       "auditor has applied a filter on the price column that
        replaces all values with $$$"
           -> NO ordinary action

    10. "intent" MUST NOT contain the canonical action name when a
        natural-language description is possible.

    11. If a matching action exists in Available Actions,
        "action" MUST NOT be null.

    12. Never invent an action.

    13. Copy action names exactly from Available Actions.

    Ordinary operation mappings:

    - select / read / query
      -> SelectFromTableAction

    - insert / insert rows / insert data
      -> InsertIntoTableAction

    - update table / update rows / modify table data
      -> UpdateTableAction

    - delete rows / delete from table
      -> DeleteFromTableAction

    - drop table / delete table
      -> DropTableAction

    - create table
      -> CreateTableAction

    - create schema
      -> CreateSchemaAction

    - create view
      -> CreateViewAction

    - create materialized view
      -> CreateMaterializedViewAction

    - drop view
      -> DropViewAction

    - drop materialized view
      -> DropMaterializedViewAction

    - drop schema
      -> DropSchemaAction

    - add column
      -> AddColumnAction

    - drop column
      -> DropColumnAction

    - rename column
      -> RenameColumnAction

    - rename table
      -> RenameTableAction

    - rename view
      -> RenameViewAction

    - rename materialized view
      -> RenameMaterializedViewAction

    - refresh materialized view
      -> RefreshMaterializedViewAction

    - truncate table
      -> TruncateTableAction

    - show tables
      -> ShowTablesAction

    - show schemas
      -> ShowSchemasAction

    - show columns
      -> ShowColumnsAction

    - show create table
      -> ShowCreateTableAction

    - show create schema
      -> ShowCreateSchemaAction

    - add/set/comment on table
      -> SetTableCommentAction

    - add/set/comment on column
      -> SetColumnCommentAction

    - add/set/comment on view
      -> SetViewCommentAction

    Effect:

    - "deny", "cannot", "not allowed", "forbidden",
      "prohibited" -> effect="deny"

    - otherwise -> effect="allow"

    One item per ordinary operation.

    A rule may mix ordinary operations with masking/filtering.

    Examples:

    Rule:
    auditor can select from employees but mask salary as '****'

    Return:
    {
      "requested_actions": [
        {
          "intent": "select from table",
          "action": "SelectFromTableAction",
          "effect": "allow"
        }
      ]
    }

    Rule:
    auditor has applied a mask to salary that replaces values with '$$$'

    Return:
    {
      "requested_actions": []
    }

    Rule:
    auditor has applied a filter on column price that replaces
    all price values with '$$$'

    Return:
    {
      "requested_actions": []
    }
    """

    result = _llm_json( system_prompt, ( "Available Actions:\n" + json.dumps( available_actions, ensure_ascii=False, indent=2 ) + "\n\nRule:\n" + rule ), is_local=is_local, chat_url=chat_url, client=client, model=model )
    if set(result.keys()) != {"requested_actions"}:
        raise ValueError("Action extraction returned invalid JSON.")
    items = result.get("requested_actions")
    if not isinstance(items, list):
        raise ValueError("'requested_actions' must be a list.")
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            continue
        effect = item.get("effect")
        if effect not in EFFECTS:
            raise ValueError(f"Invalid effect: {effect!r}")
        normalized.append({ "intent": item.get("intent", ""), "action": item.get("action"), "effect": effect })
    return normalized

# ============================================================================
# Split allow / deny
# ============================================================================

def _split_allowed_deny( requested_actions, available_actions ):
    available = set(available_actions)
    allowed = []
    deny = []
    for item in requested_actions:
        action = item.get("action")
        if action not in available:
            continue
        target = ( deny if item.get("effect") == "deny" else allowed )
        if action not in target:
            target.append(action)
    conflicts = sorted( set(allowed) & set(deny) )
    return allowed, deny, conflicts

# ============================================================================
# Final explanation
# ============================================================================

def _build_explanation_text( rule, group, resource, allowed, deny, column_masks=None, row_filter=None ):
    parts = [ f"{k} {resource[k]}" for k in ("catalog", "schema", "table", "column") if resource.get(k) ]
    scope = ", ".join(parts) or "no specific resource"
    text = ( f"Group {group or 'unknown'}: " f"allowed {allowed or 'none'}, " f"denied {deny or 'none'}, " f"on {scope}." )
    if column_masks:
        text += f" Column masks: {column_masks}."
    if row_filter:
        text += f" Row filter: {row_filter}."
    return text

def _generate_final_explanation( rule, security_group_result, resource, expanded_resources, allowed, deny, path_result, effects, examples, is_local, chat_url=None, client=None, model=None, data_mesh_structure=None ):
    return _build_explanation_text( rule=rule, group=security_group_result.get("security_group"), resource=resource, allowed=allowed, deny=deny, column_masks=effects.get("column_masks", {}), row_filter=effects.get("row_filter") )
# ============================================================================
# Main
# ============================================================================

def llm_explain( rule, example_index, data_mesh_structure, security_groups, available_actions, is_local, n=3, chat_url=None, embedding_url=None, client=None, model=None, embedding_model=None ):
    if not isinstance(rule, str) or not rule.strip():
        raise ValueError( "The rule must be a non-empty string." )
    rule = rule.strip()
    # Normalize authoritative Data Mesh once.
    data_mesh_structure = _normalize_data_mesh_structure( data_mesh_structure )
    security_groups = [ group for group in ( security_groups if isinstance(security_groups, list) else [] ) if isinstance(group, str) and group.strip() ]
    available_actions = _normalize_available_actions( available_actions )

    # ------------------------------------------------------------------------
    # Examples
    # ------------------------------------------------------------------------
    examples = []
    if example_index:
        examples = find_best_examples( rule=rule, index=example_index, is_local=is_local, n=n, embedding_url=embedding_url, client=client, embedding_model=embedding_model )

    # ------------------------------------------------------------------------
    # Security group
    # ------------------------------------------------------------------------
    security_group_result = _extract_security_group( rule=rule, security_groups=security_groups, is_local=is_local, chat_url=chat_url, client=client, model=model )

    # ------------------------------------------------------------------------
    # Resource
    # ------------------------------------------------------------------------
    resource = _extract_resource( rule=rule, data_mesh_structure=data_mesh_structure, is_local=is_local, chat_url=chat_url, client=client, model=model )

    # ------------------------------------------------------------------------
    # Validate resource
    # ------------------------------------------------------------------------
    path_result = _validate_resource_path( resource=resource, data_mesh_structure=data_mesh_structure )

    # ------------------------------------------------------------------------
    # Expand only after successful validation.
    #
    # Schema-level rules expand to concrete tables.
    # This is only for compilation; the original resource scope remains
    # schema-level.
    # ------------------------------------------------------------------------
    expanded_resources = []
    if path_result["valid"]:
        expanded_resources = _expand_resource( resource=resource, data_mesh_structure=data_mesh_structure )

    # ------------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------------
    requested_actions = _extract_actions( rule=rule, available_actions=available_actions, is_local=is_local, chat_url=chat_url, client=client, model=model, examples=examples )
    print( "[DEBUG] Raw requested_actions:", json.dumps( requested_actions, indent=2, ensure_ascii=False ) )
    requested_actions = _normalize_extracted_actions( requested_actions=requested_actions, available_actions=available_actions )
    print( "[DEBUG] Normalized requested_actions:", json.dumps( requested_actions, indent=2, ensure_ascii=False ) )
    action_result = _validate_actions( requested_actions=requested_actions, available_actions=available_actions )
    allowed, deny, conflicts = _split_allowed_deny( requested_actions, available_actions )

    # ------------------------------------------------------------------------
    # Row filter / column mask
    # -----------------------------------------------------------------------
    effects = _extract_effects( rule=rule, resource=resource, data_mesh_structure=data_mesh_structure, is_local=is_local, chat_url=chat_url, client=client, model=model )
    effects_result = _validate_effects( effects=effects, resource=resource, data_mesh_structure=data_mesh_structure )

    # ------------------------------------------------------------------------
    # Feedback
    # ------------------------------------------------------------------------
    feedback = []
    for part in ( security_group_result, path_result, action_result, effects_result ):
        if part.get("feedback"):
            feedback.append( part["feedback"] )
    if conflicts:
        feedback.append( "The same action is both allowed and denied: " + ", ".join( repr(x) for x in conflicts ) + "." )
    resource_was_requested = any( resource.get(field) for field in RESOURCE_FIELDS )
    if ( path_result["valid"] and resource_was_requested and not expanded_resources ):
        feedback.append( "The requested resource path is valid syntactically, " "but it does not resolve to any concrete table or " "column in the Data Mesh Structure." )

    # ------------------------------------------------------------------------
    # Final explanation
    # ------------------------------------------------------------------------

    text = _generate_final_explanation(
        rule=rule,
        security_group_result=security_group_result,
        resource=resource,
        expanded_resources=expanded_resources,
        allowed=allowed,
        deny=deny,
        path_result=path_result,
        effects=effects,
        examples=examples,
        is_local=is_local,
        chat_url=chat_url,
        client=client,
        model=model,
        data_mesh_structure=data_mesh_structure
    )

    # ------------------------------------------------------------------------
    # Return
    # ------------------------------------------------------------------------

    rewritten_rule = {
        "text": text,
        "securityGroup": security_group_result["security_group"],
        "existSecureGroup": security_group_result["existSecureGroup"],
        "pathExistOnDataMeshStructure": path_result["valid"],
        "actionExist": action_result["valid"] and not conflicts,
        "resource": { "catalog": resource.get("catalog") or "", "schema": resource.get("schema") or "", "table": resource.get("table") or "", "column": resource.get("column") or "" },
        "allowed": allowed,
        "deny": deny,
        "row_filter": effects.get("row_filter"),
        "column_masks": effects.get("column_masks", {}),
        "expandedResources": expanded_resources,
        "llm_feedback": " ".join(feedback)
    }

    with REWRITTEN_RULE_PATH.open( "w", encoding="utf-8" ) as f:
        json.dump( rewritten_rule, f, indent=4 )
    return rewritten_rule
