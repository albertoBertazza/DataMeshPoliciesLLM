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
FILTER_TYPES = { "catalog": "FilterCatalogs", "schema": "FilterSchemas", "table": "FilterTables", "column": "FilterColumns" }
FILTER_EFFECT_FIELDS = set(FILTER_TYPES.values())
FILTER_KEYS = ( "FilterCatalogs", "FilterSchemas", "FilterTables", "FilterColumns" )

# ============================================================================
# Metadata visibility filters
# ============================================================================
def _extract_visibility_filters( rule, resource, data_mesh_structure, is_local, chat_url=None, client=None, model=None ):
    """
    Extract metadata visibility declarations.

    Ordinary SHOW/LIST operations must never create metadata
    visibility filters.
    """

    # --------------------------------------------------------------
    # CRITICAL GATE
    # --------------------------------------------------------------
    if not _is_metadata_visibility_declaration(rule):
        return { "FilterCatalogs": { "allowed": [], "deny": [] }, "FilterSchemas": { "allowed": [], "deny": [] }, "FilterTables": { "allowed": [], "deny": [] }, "FilterColumns": { "allowed": [], "deny": [] } }

    system_prompt = """
Extract metadata visibility declarations from an authorization rule.

Return ONLY this JSON structure:

{
  "FilterCatalogs": {
    "allowed": [],
    "deny": []
  },
  "FilterSchemas": {
    "allowed": [],
    "deny": []
  },
  "FilterTables": {
    "allowed": [],
    "deny": []
  },
  "FilterColumns": {
    "allowed": [],
    "deny": []
  }
}

These filters control metadata visibility.

They are NOT ordinary Trino authorization actions.

Definitions:

- FilterCatalogs = visibility of catalogs
- FilterSchemas  = visibility of schemas
- FilterTables   = visibility of tables
- FilterColumns  = visibility of columns

CRITICAL RULE:

Only put an object into the filter corresponding to the
OBJECT WHOSE VISIBILITY IS BEING CHANGED.

For example:

"auditor cannot see hr schema inside iceberg"

MUST return:

{
  "FilterCatalogs": {
    "allowed": [],
    "deny": []
  },
  "FilterSchemas": {
    "allowed": [],
    "deny": ["hr"]
  },
  "FilterTables": {
    "allowed": [],
    "deny": []
  },
  "FilterColumns": {
    "allowed": [],
    "deny": []
  }
}

The catalog "iceberg" is only the parent/context of the schema.
It MUST NOT be added to FilterCatalogs.

Another example:

"auditor cannot see iceberg catalog"

MUST return:

{
  "FilterCatalogs": {
    "allowed": [],
    "deny": ["iceberg"]
  },
  "FilterSchemas": {
    "allowed": [],
    "deny": []
  },
  "FilterTables": {
    "allowed": [],
    "deny": []
  },
  "FilterColumns": {
    "allowed": [],
    "deny": []
  }
}

Another example:

"auditor cannot see people table inside hr schema"

MUST return:

{
  "FilterCatalogs": {
    "allowed": [],
    "deny": []
  },
  "FilterSchemas": {
    "allowed": [],
    "deny": []
  },
  "FilterTables": {
    "allowed": [],
    "deny": ["people"]
  },
  "FilterColumns": {
    "allowed": [],
    "deny": []
  }
}

Another example:

"auditor cannot see salary column of people"

MUST return:

{
  "FilterCatalogs": {
    "allowed": [],
    "deny": []
  },
  "FilterSchemas": {
    "allowed": [],
    "deny": []
  },
  "FilterTables": {
    "allowed": [],
    "deny": []
  },
  "FilterColumns": {
    "allowed": [],
    "deny": ["salary"]
  }
}

IMPORTANT:

A parent resource mentioned only to locate the target is NOT
itself a visibility restriction.

For:

"cannot see hr schema inside iceberg"

- iceberg = parent/context
- hr = object being hidden

Therefore:

FilterCatalogs.deny = []
FilterSchemas.deny = ["hr"]

Do NOT propagate a deny from a child object to its parent.

Only explicitly mentioned visibility targets may be extracted.

Do not invent names.

Preserve names exactly.

A negative visibility statement means deny.

A positive visibility statement means allowed.

Examples:

"auditor can see hr schema"

means:

FilterSchemas.allowed = ["hr"]

"auditor cannot see hr schema"

means:

FilterSchemas.deny = ["hr"]

"auditor can see people table"

means:

FilterTables.allowed = ["people"]

"auditor cannot see people table"

means:

FilterTables.deny = ["people"]

"auditor can see salary column"

means:

FilterColumns.allowed = ["salary"]

"auditor cannot see salary column"

means:

FilterColumns.deny = ["salary"]

If there is no metadata visibility declaration,
all lists must be empty.

Do not create ordinary authorization actions.

Do not create row filters.

Do not create column masks.

CRITICAL DISTINCTION BETWEEN VISIBILITY AND COLUMN MASKING:

FilterColumns means that the COLUMN ITSELF is hidden from metadata.

A column mask means that the COLUMN REMAINS VISIBLE, but its VALUES
are transformed, obfuscated, redacted, or replaced.

Therefore:

"auditor cannot see employee_id column in the list of columns"
-> FilterColumns.deny = ["employee_id"]

BUT:

"auditor cannot see employee_id in clear text"
"auditor cannot see employee_id values"
"auditor must see employee_id as ****"
"mask employee_id with asterisks"
"redact employee_id"
"obfuscate employee_id"
"replace employee_id values with ****"

-> These are COLUMN MASKS.
-> Do NOT populate FilterColumns.
-> Return all Filter* lists empty.

The words "cannot see" alone do NOT imply FilterColumns.
You must determine whether the rule hides the COLUMN METADATA or
hides/transforms the COLUMN VALUES.

If the rule mentions:
- clear text
- plain text
- values
- masked
- mask
- asterisks
- ****
- redacted
- obfuscated
- replaced values

then it is a column mask, not a metadata visibility filter.
"""
    context = { "rule": rule, "resource": resource, "data_mesh_structure": data_mesh_structure }
    result = _llm_json( system_prompt, json.dumps( context, ensure_ascii=False, indent=2 ), is_local=is_local, chat_url=chat_url, client=client, model=model )
    if set(result.keys()) != set(FILTER_KEYS):
        raise ValueError( "Metadata visibility filter extraction returned " "invalid JSON. " f"Received: {json.dumps(result, ensure_ascii=False)}" )
    normalized = {}
    for filter_key in FILTER_KEYS:
        value = result.get(filter_key)
        if not isinstance(value, dict):
            raise ValueError( f"'{filter_key}' must be an object." )
        if set(value.keys()) != {"allowed", "deny"}:
            raise ValueError( f"'{filter_key}' must contain exactly " "'allowed' and 'deny'." )
        allowed = value.get("allowed")
        deny = value.get("deny")
        if not isinstance(allowed, list):
            raise ValueError( f"'{filter_key}.allowed' must be a list." )
        if not isinstance(deny, list):
            raise ValueError( f"'{filter_key}.deny' must be a list." )
        normalized_allowed = []
        normalized_deny = []
        for item in allowed:
            if not isinstance(item, str):
                raise ValueError( f"All values in '{filter_key}.allowed' " "must be strings." )
            item = item.strip()
            if item and item not in normalized_allowed:
                normalized_allowed.append(item)
        for item in deny:
            if not isinstance(item, str):
                raise ValueError( f"All values in '{filter_key}.deny' " "must be strings." )
            item = item.strip()
            if item and item not in normalized_deny:
                normalized_deny.append(item)
        conflicts = ( set(normalized_allowed) & set(normalized_deny) )
        if conflicts:
            raise ValueError( f"'{filter_key}' contains objects in both " f"'allowed' and 'deny': " + ", ".join(sorted(conflicts)) )
        normalized[filter_key] = { "allowed": normalized_allowed, "deny": normalized_deny }

    # ==================================================================
    # Deterministic semantic correction
    # ==================================================================
    #
    # The resource extractor already tells us the semantic target.
    #
    # If this is a metadata visibility rule targeting a schema,
    # FilterSchemas is the only filter level that may be populated
    # unless the rule explicitly contains another independent target.
    #
    # This prevents:
    #
    #     schema hr inside iceberg
    #
    # from becoming:
    #
    #     FilterCatalogs.deny = ["iceberg"]
    #     FilterSchemas.deny = ["hr"]
    #
    # ==================================================================
    if _is_metadata_visibility_restriction(rule):
        resource_catalog = resource.get("catalog")
        resource_schema = resource.get("schema")
        resource_table = resource.get("table")
        resource_column = resource.get("column")
        rule_lower = re.sub( r"\s+", " ", rule.lower().strip() )

        # --------------------------------------------------------------
        # Schema visibility
        # --------------------------------------------------------------
        if resource_schema and not resource_table:
            schema_mentioned = bool( re.search( r"\b(?:schema|schemas)\b", rule_lower ) )
            if schema_mentioned:
                schema_filter = normalized["FilterSchemas"]

                # The resource schema is the actual visibility target.
                # Keep only the schema target returned by the LLM.
                #
                # The parent catalog is context, not a hidden object.
                normalized["FilterCatalogs"] = { "allowed": [], "deny": [] }
                normalized["FilterTables"] = { "allowed": [], "deny": [] }
                normalized["FilterColumns"] = { "allowed": [], "deny": [] }

                # If the LLM failed to put the schema in the correct
                # filter, deterministically recover the explicit
                # resource target from the negative/positive wording.
                if ( not schema_filter["allowed"] and not schema_filter["deny"] and resource_schema ):
                    negative = bool( re.search( r"\b(" r"cannot|can't|can not|" r"not allowed to|must not|" r"should not|do not|don't|" r"hide|hidden" r")\b", rule_lower ) )
                    positive = bool( re.search( r"\b(" r"can see|can show|" r"is allowed to see|" r"should see|" r"should be able to see" r")\b", rule_lower ) )
                    if negative:
                        schema_filter["deny"] = [ resource_schema ]
                    elif positive:
                        schema_filter["allowed"] = [ resource_schema ]

        # --------------------------------------------------------------
        # Table visibility
        # --------------------------------------------------------------
        elif resource_table and not resource_column:
            normalized["FilterCatalogs"] = { "allowed": [], "deny": [] }
            normalized["FilterSchemas"] = { "allowed": [], "deny": [] }
            normalized["FilterColumns"] = { "allowed": [], "deny": [] }

        # --------------------------------------------------------------
        # Column visibility
        # --------------------------------------------------------------
        elif resource_column:
            normalized["FilterCatalogs"] = { "allowed": [], "deny": [] }
            normalized["FilterSchemas"] = { "allowed": [], "deny": [] }
            normalized["FilterTables"] = { "allowed": [], "deny": [] }
    return normalized

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
    Return normalized column definitions.

    Supports:

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
        # Legacy format
        if isinstance(column, str):
            if column:
                result.append({ "name": column, "type": "varchar" })
            continue
        # Authoritative Data Mesh format
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
    if not isinstance(column_name, str) or not column_name:
        return None
    for column in _get_columns(table):
        if column.get("name") == column_name:
            return column.get("type", "varchar")
    return None

def _find_column_definition( data_mesh_structure, catalog_name, schema_name, table_name, column_name ):
    catalog = _find_catalog(data_mesh_structure, catalog_name)
    if catalog is None:
        return None
    schema = _find_schema(catalog, schema_name)
    if schema is None:
        return None
    table = _find_table(schema, table_name)
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
            return { "valid": False, "feedback": ( f"Resource field '{field}' must be a string or null." ) }

    catalog_name = resource.get("catalog")
    schema_name = resource.get("schema")
    table_name = resource.get("table")
    column_name = resource.get("column")

    # No resource specified.
    if not any([ catalog_name, schema_name, table_name, column_name ]):
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
        return { "valid": False, "feedback": ( f"The catalog '{catalog_name}' does not exist. " "Available catalogs are: " + ( ", ".join(repr(x) for x in available) if available else "none" ) + "." ) }

    # Catalog-only.
    if not schema_name:
        return { "valid": True, "feedback": "" }

    # Schema.
    schema = _find_schema( catalog, schema_name )
    if schema is None:
        available = _get_schema_names(catalog)
        return { "valid": False, "feedback": ( f"The schema '{schema_name}' does not exist " f"in catalog '{catalog_name}'. " "Available schemas are: " + ( ", ".join(repr(x) for x in available) if available else "none" ) + "." ) }

    # Schema-only authorization is valid.
    if not table_name:
        return { "valid": True, "feedback": "" }
    # Table.
    table = _find_table( schema, table_name )
    if table is None:
        available = _get_table_names(schema)
        return {
            "valid": False,
            "feedback": ( f"The table '{table_name}' does not exist " f"in catalog '{catalog_name}', " f"schema '{schema_name}'. " "Available tables are: " + ( ", ".join(repr(x) for x in available) if available else "none" ) + "." )
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

def _is_column_mask_declaration(rule):
    """
    Return True when the rule describes masking/obfuscating the VALUE
    of a column rather than hiding the column metadata itself.
    """
    text = re.sub(r"\s+", " ", rule.lower().strip())
    mask_patterns = (
        r"\bmask(?:ed|ing)?\b",
        r"\bobfuscat(?:e|ed|ing)\b",
        r"\bredact(?:ed|ing)?\b",
        r"\banonymiz(?:e|ed|ing)\b",
        r"\breplace\b.*\bwith\b",
        r"\basterisks?\b",
        r"\b\*{2,}\b",
        r"\bclear text\b",
        r"\bplain text\b",
        r"\bin clear\b",
        r"\bhide\b.*\bvalues?\b",
        r"\bhidden\b.*\bvalues?\b",
        r"\btransform\b.*\bvalues?\b",
    )
    return any(re.search(pattern, text) for pattern in mask_patterns)

def _is_metadata_visibility_restriction(rule):
    """
    Return True when the rule changes metadata visibility rather
    than masking column values or denying execution of SHOW/LIST.
    """
    text = re.sub(r"\s+", " ", rule.lower().strip())

    # --------------------------------------------------------------
    # COLUMN MASK HAS PRIORITY
    #
    # Example:
    #   "auditor can't see employee_id in clear text;
    #    it should be masked with asterisks"
    #
    # This is NOT metadata visibility.
    # --------------------------------------------------------------
    if _is_column_mask_declaration(rule):
        return False
    visibility_verb = re.search( r"\b(see|view|show|list|display)\b", text )
    negative_visibility = re.search( r"\b(" r"cannot|can't|can not|" r"not allowed to|must not|should not|" r"do not|don't|hide|hidden" r")\b", text )
    metadata_target = re.search( r"\b(" r"catalog|catalogs|" r"schema|schemas|" r"table|tables|" r"column|columns" r")\b", text )
    execution_denial = re.search( r"\b(execute|run|perform)\b.*\b(show|list)\b", text )
    return bool( visibility_verb and negative_visibility and metadata_target and not execution_denial )

def _is_metadata_visibility_declaration(rule):
    """
    Return True only when the rule explicitly changes metadata
    visibility.

    Column masking always takes precedence over metadata visibility.

    Examples:

        "auditor cannot see people table"
            -> FilterTables

        "auditor cannot see employee_id in clear text"
            -> column mask

        "auditor masks employee_id with ****"
            -> column mask

        "auditor cannot see employee_id column in the list of columns"
            -> FilterColumns
    """
    text = re.sub(r"\s+", " ", rule.lower().strip())

    # --------------------------------------------------------------
    # CRITICAL:
    # A mask/redaction/value-transformation is NOT metadata
    # visibility, even if the sentence contains "cannot see".
    # --------------------------------------------------------------
    if _is_column_mask_declaration(rule):
        return False
    # --------------------------------------------------------------
    # Explicit negative visibility
    # --------------------------------------------------------------
    negative_visibility = re.search(
        r"\b("
        r"cannot see|can't see|can not see|"
        r"cannot view|can't view|can not view|"
        r"cannot access|can't access|can not access|"
        r"not allowed to see|"
        r"not allowed to view|"
        r"must not see|"
        r"must not view|"
        r"should not see|"
        r"should not view|"
        r"do not see|don't see|"
        r"do not view|don't view|"
        r"hide|hidden|"
        r"not visible|"
        r"not be visible"
        r")\b",
        text
    )
    # --------------------------------------------------------------
    # Explicit positive visibility
    # --------------------------------------------------------------
    positive_visibility = re.search( r"\b(" r"can see|" r"can view|" r"is allowed to see|" r"is allowed to view|" r"should see|" r"should be able to see|" r"should view|" r"should be able to view" r")\b", text )
    # --------------------------------------------------------------
    # Metadata object must be present.
    # --------------------------------------------------------------
    metadata_target = re.search( r"\b(" r"catalog|catalogs|" r"schema|schemas|" r"table|tables|" r"column|columns" r")\b", text )
    if not metadata_target:
        return False
    return bool( negative_visibility or positive_visibility )

def _normalize_extracted_actions( requested_actions, available_actions ):
    """
    Normalize LLM action extraction.

    Important:
    An action is only accepted if it exists in available_actions.

    This prevents unsupported actions such as:
        SelectFromTableAction
        UpdateTableAction

    from being silently inserted into the policy when they are not
    actually defined by the current Trino action mapping.
    """

    available = set(available_actions)

    # ------------------------------------------------------------------
    # Natural language -> canonical action mappings.
    #
    # These are candidates only. They are accepted only when the
    # canonical action exists in `available_actions`.
    # ------------------------------------------------------------------

    exact_mappings = {

        # SELECT / READ
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
        #
        # Current action mapping uses UpdateTableColumnsAction.
        "update": "UpdateTableColumnsAction",
        "update table": "UpdateTableColumnsAction",
        "update a table": "UpdateTableColumnsAction",
        "update rows": "UpdateTableColumnsAction",
        "update table columns": "UpdateTableColumnsAction",
        "update column values": "UpdateTableColumnsAction",
        "modify table data": "UpdateTableColumnsAction",
        "modify rows in table": "UpdateTableColumnsAction",

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

        # CREATE TABLE
        "create table": "CreateTableAction",
        "create a table": "CreateTableAction",
        "creating table": "CreateTableAction",
        "make a table": "CreateTableAction",

        # CREATE SCHEMA
        "create schema": "CreateSchemaAction",
        "create a schema": "CreateSchemaAction",
        "creating schema": "CreateSchemaAction",
        "make a schema": "CreateSchemaAction",

        # CREATE VIEW
        "create view": "CreateViewAction",
        "create a view": "CreateViewAction",
        "creating view": "CreateViewAction",
        "make a view": "CreateViewAction",

        # CREATE MATERIALIZED VIEW
        "create materialized view": "CreateMaterializedViewAction",
        "create a materialized view": "CreateMaterializedViewAction",
        "creating materialized view": "CreateMaterializedViewAction",
        "make a materialized view": "CreateMaterializedViewAction",

        # DROP TABLE
        "drop table": "DropTableAction",
        "drop a table": "DropTableAction",
        "delete table": "DropTableAction",
        "delete a table": "DropTableAction",
        "remove table": "DropTableAction",
        "remove a table": "DropTableAction",

        # DROP VIEW
        "drop view": "DropViewAction",
        "drop a view": "DropViewAction",
        "delete view": "DropViewAction",
        "delete a view": "DropViewAction",
        "remove view": "DropViewAction",

        # DROP MATERIALIZED VIEW
        "drop materialized view": "DropMaterializedViewAction",
        "drop a materialized view": "DropMaterializedViewAction",
        "delete materialized view": "DropMaterializedViewAction",
        "delete a materialized view": "DropMaterializedViewAction",
        "remove materialized view": "DropMaterializedViewAction",

        # DROP SCHEMA
        "drop schema": "DropSchemaAction",
        "drop a schema": "DropSchemaAction",
        "delete schema": "DropSchemaAction",
        "delete a schema": "DropSchemaAction",
        "remove schema": "DropSchemaAction",

        # ADD COLUMN
        "add column": "AddColumnAction",
        "add a column": "AddColumnAction",
        "adding column": "AddColumnAction",

        # DROP COLUMN
        "drop column": "DropColumnAction",
        "drop a column": "DropColumnAction",
        "delete column": "DropColumnAction",
        "delete a column": "DropColumnAction",
        "remove column": "DropColumnAction",
        "remove a column": "DropColumnAction",

        # RENAME COLUMN
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

        # REFRESH MATERIALIZED VIEW
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
        "see tables": "ShowTablesAction",
        "see table": "ShowTablesAction",
        "view tables": "ShowTablesAction",
        "view table": "ShowTablesAction",
        "access tables": "ShowTablesAction",

        # SHOW SCHEMAS
        "show schemas": "ShowSchemasAction",
        "show schema": "ShowSchemasAction",
        "list schemas": "ShowSchemasAction",
        "list schema": "ShowSchemasAction",
        "show available schemas": "ShowSchemasAction",
        "list available schemas": "ShowSchemasAction",
        "see schemas": "ShowSchemasAction",
        "see schema": "ShowSchemasAction",
        "view schemas": "ShowSchemasAction",
        "view schema": "ShowSchemasAction",
        "access schemas": "ShowSchemasAction",

        # SHOW COLUMNS
        "show columns": "ShowColumnsAction",
        "show table columns": "ShowColumnsAction",
        "list columns": "ShowColumnsAction",
        "list table columns": "ShowColumnsAction",
        "view columns": "ShowColumnsAction",
        "see columns": "ShowColumnsAction",
        "see table columns": "ShowColumnsAction",
        "view table columns": "ShowColumnsAction",
        "access columns": "ShowColumnsAction",

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
    # Longest phrases first.
    contains_mappings = sorted( exact_mappings.items(), key=lambda item: len(item[0]), reverse=True )
    normalized = []
    for item in requested_actions:
        if not isinstance(item, dict):
            continue
        intent = str( item.get("intent", "") ).strip()
        action = item.get("action")
        effect = item.get( "effect", "allow" )
        normalized_intent = re.sub( r"\s+", " ", intent.lower().strip() )

        # --------------------------------------------------------------
        # 1. Already valid canonical action.
        # --------------------------------------------------------------
        if action in available:
            normalized.append({ "intent": intent, "action": action, "effect": effect })
            continue

        # --------------------------------------------------------------
        # 2. Canonical action returned inside intent.
        # --------------------------------------------------------------
        if action is None and intent in available:
            action = intent

        # --------------------------------------------------------------
        # 3. Exact mapping.
        # --------------------------------------------------------------
        if action is None:
            candidate = exact_mappings.get( normalized_intent )
            if candidate in available:
                action = candidate
        # --------------------------------------------------------------
        # 4. Visibility patterns.
        #
        # Handles:
        #
        #   see schema
        #   see hr schema
        #   see the hr schema
        #   see tables
        #   see tables inside hr
        #   see columns of people
        #   view columns of people
        #   list available tables
        # --------------------------------------------------------------
        if action is None:
            visibility_patterns = [
                # Schema visibility
                ( r"\b(?:see|view|show|list|access)\s+" r"(?:the\s+)?" r"(?:[a-zA-Z_][a-zA-Z0-9_.-]*\s+)?" r"schemas?\b", "ShowSchemasAction" ),

                # Table visibility
                ( r"\b(?:see|view|show|list|access)\s+" r"(?:the\s+)?" r"(?:available\s+)?" r"tables?\b", "ShowTablesAction" ),

                # Column visibility
                ( r"\b(?:see|view|show|list|access)\s+" r"(?:the\s+)?" r"(?:available\s+)?" r"columns?\b", "ShowColumnsAction" ),

                # Column visibility with "of"
                ( r"\b(?:see|view|show|list|access)\s+" r"(?:the\s+)?" r"columns?\s+of\b", "ShowColumnsAction" ),
            ]
            for pattern, mapped_action in visibility_patterns:
                if mapped_action not in available:
                    continue
                if re.search( pattern, normalized_intent ):
                    action = mapped_action
                    break

        # --------------------------------------------------------------
        # 5. Generic contained phrase mapping.
        # --------------------------------------------------------------
        if action is None:
            for phrase, mapped_action in contains_mappings:
                if phrase not in normalized_intent:
                    continue
                if mapped_action in available:
                    action = mapped_action
                    break
        normalized.append({ "intent": intent, "action": action, "effect": effect })
    return normalized

def _validate_actions( requested_actions, available_actions ):
    """
    Validate ordinary Trino actions.

    Empty action list is valid because a rule may contain only
    a column mask or row filter.
    """
    if not isinstance(requested_actions, list):
        return { "valid": False, "feedback": ( "The extracted actions are not a valid list." ) }
    available = set(available_actions)
    invalid = []
    valid = []
    for item in requested_actions:
        if not isinstance(item, dict):
            invalid.append({ "intent": "", "action": None })
            continue
        intent = item.get( "intent", "" )
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
                messages.append( f"The requested operation " f"'{item['intent']}' could not be mapped " f"to any available action." )
            else:
                messages.append( f"The inferred action " f"'{item['action']}' is not in the available actions." )
        messages.append( "Available actions are: " + ( ", ".join(available_actions) if available_actions else "none" ) + "." )
        return { "valid": False, "feedback": " ".join(messages) }
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
    response = llm_call( messages=messages, temperature=0.0, response_format={"type": "json_object"}, max_tokens=7000, is_local=is_local, chat_url=chat_url, client=client, model=model )
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
        return { "security_group": None, "existSecureGroup": False, "feedback": "No security group could be identified in the request."}
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

def _extract_security_group_local(rule,security_groups,is_local,chat_url=None,client=None, model=None,):
    system_prompt = """
You extract security groups from authorization rules.

Return ONLY a valid JSON object with exactly this field:
{"security_group": null}

Rules:
1. Examine the complete authorization rule.
2. Match explicitly mentioned security group names against the
   provided list of available security groups.
3. A group is explicitly mentioned even when the sentence uses
   negative wording, such as "cannot", "can not", "must not",
   "deny", or "not allowed".
4. Do not confuse resource names, catalog names, schema names,
   table names, or action names with security groups.
5. Do not infer a group from context.
6. Preserve the exact spelling of the matched group.
7. If no available security group is explicitly mentioned,
   return null.
8. Return no other fields or explanations.
"""
    user_prompt = ( "Available security groups:\n" + json.dumps(security_groups, ensure_ascii=False) + "\n\nAuthorization rule:\n" + rule + '\n\nExtract the explicitly mentioned security group.' )
    print("Security group extraction input:", user_prompt)
    result = _llm_json(system_prompt,user_prompt,is_local=is_local, chat_url=chat_url, client=client, model=model)
    if not isinstance(result, dict) or set(result.keys()) != { "security_group" }:
        raise ValueError( "Security group extraction returned invalid JSON." )
    group = result["security_group"]
    if group is None or group == "":
        return { "security_group": None, "existSecureGroup": False, "feedback": ( "No security group could be identified in the request." )}
    if not isinstance(group, str):
        raise ValueError("'security_group' must be a string or null.")
    group = group.strip()
    if group in security_groups:
        return { "security_group": group, "existSecureGroup": True, "feedback": ""}
    return {
        "security_group": group,
        "existSecureGroup": False,
        "feedback": ( f"The security group '{group}' does not exist. " "Available security groups are: " + ( ", ".join(repr(x) for x in security_groups) if security_groups else "none" ) + "." ),
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
    12. A rule about "columns of table X" is table-level unless
        a specific column is explicitly named.
    13. Do NOT choose an arbitrary table when the rule is schema-level.
    14. Return no other fields.

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

    "auditor cannot see the hr schema inside iceberg"

    {
      "catalog": "iceberg",
      "schema": "hr",
      "table": null,
      "column": null
    }

    "auditor cannot see columns of people inside hr"

    {
      "catalog": null,
      "schema": "hr",
      "table": "people",
      "column": null
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
            resource[field] = ( value if value else None )

    # ------------------------------------------------------------------
    # Deterministic table recovery.
    #
    # Only recover a table when exactly one existing table name is
    # explicitly present in the rule.
    # ------------------------------------------------------------------
    if ( resource["table"] is None and resource["schema"] is not None and resource["catalog"] is not None ):
        catalog = _find_catalog( data_mesh_structure, resource["catalog"] )
        schema = _find_schema( catalog, resource["schema"] )
        if schema is not None:
            candidate_tables = []
            rule_lower = rule.lower()
            for table_name in _get_table_names(schema):
                pattern = ( r"\b" + re.escape(table_name.lower()) + r"\b" )
                if re.search( pattern, rule_lower ):
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
    path_result = _validate_resource_path( resource, data_mesh_structure )
    if not path_result["valid"]:
        return { "row_filter": None, "column_masks": {} }
    resource_column = resource.get("column")
    column_type = None
    if ( resource.get("catalog") and resource.get("schema") and resource.get("table") and resource_column ):
        column_definition = _find_column_definition( data_mesh_structure=data_mesh_structure, catalog_name=resource["catalog"], schema_name=resource["schema"], table_name=resource["table"], column_name=resource_column )
        if column_definition is not None:
            column_type = column_definition.get("type")
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

    5. A column mask MUST return the SAME SQL TYPE as the column.

    5a. ALL column-mask expressions MUST use Trino SQL syntax.

    5b. A column mask MUST return exactly ONE scalar value of the
    same type as the target column.

    5c. If the target column type is varchar, the mask MUST return
    varchar, NOT array(varchar).

    5d. NEVER wrap a scalar mask expression inside ARRAY[...] or CAST(... AS ARRAY(...)) unless the authoritative column type
    itself is an array type.

    5e. The expression must be valid as the value of a Trino
    column mask directly.

    6. The authoritative Data Mesh column type is:

       column = {resource_column or "none"}
       type   = {column_type or "unknown"}

    7. NEVER return a varchar/string expression for an integer,
    bigint, smallint, tinyint, decimal, real, double, boolean,
    date, timestamp, or other non-varchar column.

    8. Examples:

    INTEGER:
        0
        999
        CAST(0 AS integer)

    BIGINT:
        0
        CAST(0 AS bigint)

    DOUBLE:
        0.0
        CAST(0.0 AS double)

    DECIMAL:
        CAST(0 AS decimal(18,2))

    BOOLEAN:
        false
        true

    VARCHAR:
        '****'
        'hidden'

    9. If the user's requested mask is incompatible with the
    authoritative column type, convert it to a simple
    type-compatible masking expression.

    Example:

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

    13. Do not interpret a column mask as an ordinary action.

    14. If there is no row filter:
        "row_filter": null

    15. If there are no column masks:
        "column_masks": {{}}

    16. A row filter must be a SQL predicate compatible with
    the referenced Data Mesh columns.

    Examples:

    "mask email as '****'"

    {{
      "row_filter": null,
      "column_masks": {{
        "email": "'****'"
      }}
    }}

    "only show rows where department = 'HR'"

    {{
      "row_filter": "department = 'HR'",
      "column_masks": {{}}
    }}
    """
    context = { "rule": rule, "resource": resource, "column_type": column_type }
    result = _llm_json( system_prompt, json.dumps( context, ensure_ascii=False, indent=2 ), is_local=is_local, chat_url=chat_url, client=client, model=model )
    if set(result.keys()) != { "row_filter", "column_masks" }:
        raise ValueError( "Column/row effect extraction returned invalid JSON. " f"Received: {json.dumps(result, ensure_ascii=False)}" )
    row_filter = result.get("row_filter")
    column_masks = result.get("column_masks")
    if row_filter is not None and not isinstance( row_filter, str ):
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

def _extract_sql_identifiers(expression):
    """
    Extract likely column identifiers from a SQL expression.

    This is intentionally conservative. SQL keywords, literals,
    functions and qualified names are removed/ignored.
    """
    if not isinstance(expression, str):
        return []
    # Remove SQL single-quoted literals.
    expression = re.sub( r"'(?:''|[^'])*'", " ", expression )
    # Remove double-quoted literals/identifiers temporarily.
    expression = re.sub( r'"(?:""|[^"])*"', " ", expression )
    # Remove numeric literals.
    expression = re.sub( r"\b\d+(?:\.\d+)?\b", " ", expression )
    # SQL keywords / boolean literals / common operators.
    sql_keywords = {
        "and",
        "or",
        "not",
        "null",
        "true",
        "false",
        "is",
        "in",
        "like",
        "between",
        "as",
        "case",
        "when",
        "then",
        "else",
        "end",
        "cast",
        "try_cast",
        "date",
        "timestamp",
        "interval",
        "current_date",
        "current_timestamp",

        # SQL types
        "varchar",
        "char",
        "integer",
        "int",
        "bigint",
        "smallint",
        "tinyint",
        "decimal",
        "numeric",
        "real",
        "double",
        "boolean",
        "time",
    }

    # Function names.
    function_names = {
        "lower",
        "upper",
        "trim",
        "ltrim",
        "rtrim",
        "length",
        "substr",
        "substring",
        "coalesce",
        "nullif",
        "concat",
        "regexp_like",
        "regexp_extract",
        "regexp_replace",
        "date",
        "year",
        "month",
        "day",
        "hour",
        "minute",
        "second",
        "count",
        "sum",
        "avg",
        "min",
        "max",
    }
    identifiers = re.findall( r"\b[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*\b", expression )
    result = []
    for identifier in identifiers:
        normalized = identifier.split(".")[-1].lower()
        if normalized in sql_keywords:
            continue
        if normalized in function_names:
            continue
        if normalized not in result:
            result.append(normalized)
    return result

def _validate_effects( effects, resource, data_mesh_structure ):
    feedback = []
    row_filter = effects.get("row_filter")
    column_masks = effects.get( "column_masks", {} )
    if not isinstance(column_masks, dict):
        feedback.append( "'column_masks' must be an object." )
        column_masks = {}

    # ------------------------------------------------------------------
    # Column masks
    # ------------------------------------------------------------------
    if column_masks:
        resource_column = resource.get("column")
        if not resource_column:
            feedback.append( "A column mask requires a specific resource column." )
        else:
            # The mask must target exactly the resource column.
            if resource_column not in column_masks:
                feedback.append( "The column mask must target the resource column " f"'{resource_column}'." )
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            table_name = resource.get("table")
            if not catalog or not schema or not table_name:
                feedback.append( "A column mask requires a complete " "catalog/schema/table/column resource." )
            else:
                catalog_obj = _find_catalog( data_mesh_structure, catalog )
                if catalog_obj is None:
                    feedback.append( f"The mask catalog '{catalog}' " "does not exist in the Data Mesh." )
                else:
                    schema_obj = _find_schema( catalog_obj, schema )
                    if schema_obj is None:
                        feedback.append( f"The mask schema '{schema}' " f"does not exist in catalog '{catalog}'." )
                    else:
                        table_obj = _find_table( schema_obj, table_name )
                        if table_obj is None:
                            feedback.append( f"The mask table " f"'{catalog}.{schema}.{table_name}' " "does not exist in the Data Mesh." )
                        else:
                            valid_columns = set( _get_column_names(table_obj) )
                            for column in column_masks:
                                if column not in valid_columns:
                                    feedback.append(
                                        "The column mask references "
                                        f"unknown column '{column}' "
                                        f"in '{catalog}.{schema}.{table_name}'. "
                                        "Available columns are: "
                                        + ( ", ".join( repr(x) for x in sorted(valid_columns) ) if valid_columns else "none" )
                                        + "."
                                    )

    # ------------------------------------------------------------------
    # Row filter
    # ------------------------------------------------------------------
    if row_filter:
        catalog = resource.get("catalog")
        schema = resource.get("schema")
        table_name = resource.get("table")
        if not table_name:
            feedback.append( "A row filter requires a specific table." )
        elif not catalog or not schema:
            feedback.append( "A row filter requires a complete " "catalog/schema/table resource." )
        else:
            catalog_obj = _find_catalog( data_mesh_structure, catalog )
            schema_obj = _find_schema( catalog_obj, schema )
            table_obj = _find_table( schema_obj, table_name )
            if table_obj is None:
                feedback.append( f"The row filter references table " f"'{catalog}.{schema}.{table_name}', " f"but that table does not exist " f"in the Data Mesh." )
            else:
                valid_columns = set( _get_column_names(table_obj) )
                referenced_columns = ( _extract_sql_identifiers(row_filter) )
                # Case-insensitive comparison.
                valid_columns_lower = { column.lower() for column in valid_columns }
                unknown_columns = [ column for column in referenced_columns if column not in valid_columns_lower ]
                if unknown_columns:
                    feedback.append(
                        "The row filter references column(s) "
                        "that do not exist in "
                        f"'{catalog}.{schema}.{table_name}': "
                        + ", ".join( repr(x) for x in unknown_columns )
                        + ". Available columns are: "
                        + ( ", ".join( repr(x) for x in sorted(valid_columns) ) if valid_columns else "none" )
                        + "."
                    )

    # ------------------------------------------------------------------
    # Resource validity
    # ------------------------------------------------------------------
    path_result = _validate_resource_path( resource, data_mesh_structure )
    if not path_result["valid"]:
        feedback.append( path_result["feedback"] )
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

    Metadata visibility restrictions such as:

        cannot see hr schema
        cannot see tables inside hr
        cannot see columns of people

    are NOT ordinary action denials.

    They are handled by _extract_visibility_filters().
    """

    action_list = json.dumps( available_actions, ensure_ascii=False, indent=2 )

    system_prompt = f"""
Identify the intended Trino authorization operations and whether
each operation is allowed or denied.

Return ONLY:

{{
  "requested_actions": [
    {{
      "intent": "",
      "action": null,
      "effect": "allow"
    }}
  ]
}}

Available Actions:

{action_list}

Rules:

1. "intent" MUST describe an ordinary authorization operation
   in natural language.

2. "action" MUST contain the exact matching action name from
   Available Actions.

3. NEVER invent an action.

4. NEVER use an action name that is not in Available Actions.

5. Column masks and row filters are NOT ordinary actions.

6. Metadata visibility filters are NOT ordinary actions.

7. If the rule describes ONLY a column mask, row filter, or metadata visibility filter, return:

{{
  "requested_actions": []
}}

8. A column mask includes language such as:
   - mask a column
   - replace column values
   - hide column values
   - transform column values
   - apply a mask

9. A row filter includes language such as:
   - filter rows
   - restrict rows
   - only show rows where ...
   - apply a row filter
   - restrict access to rows

10. Metadata visibility filtering includes language such as:
    - cannot see a schema
    - cannot see schemas
    - not allowed to see a schema
    - must not see a schema
    - do not show a schema
    - hide a schema from the list
    - cannot see tables
    - cannot see columns
    - do not show tables
    - do not show columns
    - hide metadata from the list

    IMPORTANT DISTINCTION:

    "cannot see a column" is ambiguous.

    If the rule says the column should be:
    - masked
    - hidden in clear text
    - shown as **** - replaced with asterisks
    - transformed
    - obfuscated
    - redacted

    then this is a COLUMN MASK, NOT FilterColumns.

    Examples:

    "auditor can't see employee_id in clear text; mask it with asterisks"

    MUST NOT produce:

    FilterColumns.deny = ["employee_id"]

    It MUST produce a column mask for employee_id.

    "auditor cannot see salary column in the list of columns"

    IS a metadata visibility restriction and produces:

    FilterColumns.deny = ["salary"]

11. IMPORTANT:

    A phrase such as:

        "auditor cannot see hr schema"

    means:

        FilterSchemas = ["hr"]

    It does NOT mean:

        ShowSchemasAction + deny

12. Likewise:

        "auditor cannot see tables inside hr"

    means a metadata table visibility filter.

    It does NOT mean:

        ShowTablesAction + deny

13. Likewise:

        "auditor cannot see columns of people"

    means a metadata column visibility filter.

    It does NOT mean:

        ShowColumnsAction + deny

14. A real metadata operation denial is different.

    For example:

        "auditor is not allowed to execute SHOW SCHEMAS"

    means:

{{
  "requested_actions": [
    {{
      "intent": "show schemas",
      "action": "ShowSchemasAction",
      "effect": "deny"
    }}
  ]
}}

15. Another example:

    "auditor is not allowed to run SHOW TABLES"

    means:

{{
  "requested_actions": [
    {{
      "intent": "show tables",
      "action": "ShowTablesAction",
      "effect": "deny"
    }}
  ]
}}

16. A normal positive metadata operation is an ordinary action.

    For example:

        "auditor can show tables inside hr"

    means:

{{
  "requested_actions": [
    {{
      "intent": "show tables",
      "action": "ShowTablesAction",
      "effect": "allow"
    }}
  ]
}}

17. SELECT / READ is an ordinary data operation.

18. "update column values" is an ordinary update operation
    only when the user actually requests changing database data.

19. Effect:

    These phrases normally mean deny:

    - deny
    - denied
    - cannot
    - can't
    - not allowed
    - forbidden
    - prohibited
    - must not
    - should not

    BUT:

    When "cannot", "not allowed", "must not", etc. refer to
    metadata visibility, do NOT create an ordinary denied action.
    That case is handled by the metadata visibility filter extractor.

20. One item per ordinary operation.

21. A rule may mix ordinary operations with metadata filters,
    row filters, and column masks.

Examples:

Rule:
"auditor can not see hr schema in the list of schemas inside iceberg"

Return:

{{
  "requested_actions": []
}}

Rule:
"auditor cannot see people table in the list of tables inside hr"

Return:

{{
  "requested_actions": []
}}

Rule:
"auditor cannot see salary column in the list of columns of people"

Return:

{{
  "requested_actions": []
}}

Rule:
"auditor is not allowed to execute SHOW SCHEMAS"

Return:

{{
  "requested_actions": [
    {{
      "intent": "show schemas",
      "action": "ShowSchemasAction",
      "effect": "deny"
    }}
  ]
}}

Rule:
"auditor can show tables inside hr"

Return:

{{
  "requested_actions": [
    {{
      "intent": "show tables",
      "action": "ShowTablesAction",
      "effect": "allow"
    }}
  ]
}}

Rule:
"auditor masks salary as '****'"

Return:

{{
  "requested_actions": []
}}

Rule:
"auditor can select from employees but masks salary"

Return:

{{
  "requested_actions": [
    {{
      "intent": "select from table",
      "action": null,
      "effect": "allow"
    }}
  ]
}}

Only use a canonical action when it actually exists in Available Actions.
"""
    user_prompt = ( "Available Actions:\n" + action_list + "\n\nRule:\n" + rule )
    if examples:
        user_prompt += ( "\n\nRelevant examples:\n" + _format_action_examples(examples) )
    result = _llm_json( system_prompt, user_prompt, is_local=is_local, chat_url=chat_url, client=client, model=model )
    if set(result.keys()) != {"requested_actions"}:
        raise ValueError( "Action extraction returned invalid JSON." )
    items = result.get("requested_actions")
    if not isinstance(items, list):
        raise ValueError( "'requested_actions' must be a list." )
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            continue
        effect = item.get("effect")
        if effect not in EFFECTS:
            raise ValueError( f"Invalid effect: {effect!r}" )
        normalized.append({ "intent": item.get("intent", ""), "action": item.get("action"), "effect": effect })
    return normalized

def _validate_visibility_filters(filters, resource, data_mesh_structure):
    """
    Validate metadata visibility filters against the authoritative
    Data Mesh structure.

    IMPORTANT:
    - FilterCatalogs validates catalog existence.
    - FilterSchemas validates schema existence.
    - FilterTables validates table existence.
    - FilterColumns validates column existence.
    - A child target must be resolved using the resource hierarchy.
    - This function does NOT treat column masks as FilterColumns.
    """

    feedback = []

    # ==============================================================
    # Structure validation
    # ==============================================================
    for key in FILTER_KEYS:
        value = filters.get( key, { "allowed": [], "deny": [] } )
        if not isinstance(value, dict):
            feedback.append( f"'{key}' must be an object." )
            continue
        if set(value.keys()) != {"allowed", "deny"}:
            feedback.append( f"'{key}' must contain exactly 'allowed' and 'deny'." )
        for effect in ("allowed", "deny"):
            if not isinstance(value.get(effect), list):
                feedback.append( f"'{key}.{effect}' must be a list." )

    # ==============================================================
    # Helpers
    # ==============================================================
    def _values(filter_key, effect):
        value = filters.get( filter_key, { "allowed": [], "deny": [] } )
        if not isinstance(value, dict):
            return []
        values = value.get(effect, [])
        if not isinstance(values, list):
            return []
        return [ value.strip() for value in values if isinstance(value, str) and value.strip() ]

    # ==============================================================
    # Resource context
    # ==============================================================
    resource_catalog = resource.get("catalog")
    resource_schema = resource.get("schema")
    resource_table = resource.get("table")
    resource_column = resource.get("column")

    # ==============================================================
    # Catalog filters
    # ==============================================================
    for effect in ("allowed", "deny"):
        for filtered_catalog in _values( "FilterCatalogs", effect ):
            catalog_obj = _find_catalog( data_mesh_structure, filtered_catalog )
            if catalog_obj is None:
                feedback.append( f"The filtered catalog " f"'{filtered_catalog}' does not exist " f"in the Data Mesh." )

    # ==============================================================
    # Schema filters
    # ==============================================================

    # A schema filter needs a catalog.
    #
    # First use the explicit resource catalog.
    #
    # If there is no catalog, try to find the schema uniquely
    # across the Data Mesh.

    for effect in ("allowed", "deny"):
        for filtered_schema in _values( "FilterSchemas", effect ):
            candidate_catalogs = []

            # ------------------------------------------------------
            # Explicit catalog from resource
            # ------------------------------------------------------
            if resource_catalog:
                catalog_obj = _find_catalog( data_mesh_structure, resource_catalog )
                if catalog_obj is not None:
                    if _find_schema( catalog_obj, filtered_schema ) is not None:
                        candidate_catalogs.append( resource_catalog )

            # ------------------------------------------------------
            # Explicit schema resource can also identify catalog
            # ------------------------------------------------------
            elif resource_schema:
                inferred_catalog = _infer_unique_catalog( data_mesh_structure, filtered_schema )
                if inferred_catalog:
                    candidate_catalogs.append( inferred_catalog )

            # ------------------------------------------------------
            # General Data Mesh lookup
            # ------------------------------------------------------
            else:
                for catalog in _get_catalogs( data_mesh_structure ):
                    if not isinstance(catalog, dict):
                        continue
                    if _find_schema( catalog, filtered_schema ) is not None:
                        catalog_name = catalog.get("name")
                        if catalog_name:
                            candidate_catalogs.append( catalog_name )
            if not candidate_catalogs:
                feedback.append( f"The filtered schema " f"'{filtered_schema}' does not exist " f"in the Data Mesh." )

    # ==============================================================
    # Table filters
    # ==============================================================
    for effect in ("allowed", "deny"):
        for filtered_table in _values( "FilterTables", effect ):
            found = False
            if resource_catalog and resource_schema:
                catalog_obj = _find_catalog( data_mesh_structure, resource_catalog )
                schema_obj = _find_schema( catalog_obj, resource_schema )
                if schema_obj is not None:
                    found = ( _find_table( schema_obj, filtered_table ) is not None )
            else:
                for catalog in _get_catalogs( data_mesh_structure ):
                    if not isinstance(catalog, dict):
                        continue
                    for schema in catalog.get("schemas", []):
                        if not isinstance(schema, dict):
                            continue
                        if _find_table( schema, filtered_table ) is not None:
                            found = True
                            break
                    if found:
                        break
            if not found:
                feedback.append( f"The filtered table '{filtered_table}' " "does not exist in the Data Mesh." )

    # ==============================================================
    # Column filters
    # ==============================================================
    for effect in ("allowed", "deny"):
        for filtered_column in _values( "FilterColumns", effect ):
            found = False
            if ( resource_catalog and resource_schema and resource_table ):
                catalog_obj = _find_catalog( data_mesh_structure, resource_catalog )
                schema_obj = _find_schema( catalog_obj, resource_schema )
                table_obj = _find_table( schema_obj, resource_table )
                if table_obj is not None:
                    found = ( filtered_column in _get_column_names(table_obj) )
            else:
                for catalog in _get_catalogs( data_mesh_structure ):
                    if not isinstance(catalog, dict):
                        continue
                    for schema in catalog.get("schemas", []):
                        if not isinstance(schema, dict):
                            continue
                        for table in schema.get("tables", []):
                            if not isinstance(table, dict):
                                continue
                            if ( filtered_column in _get_column_names(table) ):
                                found = True
                                break
                        if found:
                            break
                    if found:
                        break
            if not found:
                feedback.append( f"The filtered column '{filtered_column}' " "does not exist in the Data Mesh." )

    # ==============================================================
    # Conflicts
    # ==============================================================
    for key in FILTER_KEYS:
        allowed = set( _values(key, "allowed") )
        deny = set( _values(key, "deny") )
        conflicts = allowed & deny
        if conflicts:
            feedback.append( f"'{key}' contains the same object in both " f"'allowed' and 'deny': " + ", ".join(sorted(conflicts)) + "." )
    return { "valid": not feedback, "feedback": " ".join(feedback) }

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

def _build_explanation_text( rule, group, resource, allowed, deny, column_masks=None, row_filter=None, visibility_filters=None ):
    parts = [ f"{k} {resource[k]}" for k in ( "catalog", "schema", "table", "column" ) if resource.get(k) ]
    scope = ", ".join(parts) or "no specific resource"
    text = ( f"Group {group or 'unknown'}: " f"allowed {allowed or 'none'}, " f"denied {deny or 'none'}, " f"on {scope}." )
    if column_masks:
        text += f" Column masks: {column_masks}."
    if row_filter:
        text += f" Row filter: {row_filter}."
    visibility_filters = visibility_filters or {}
    active_filters = {}
    for key in FILTER_KEYS:
        value = visibility_filters.get( key, { "allowed": [], "deny": [] } )
        if not isinstance(value, dict):
            continue
        if value.get("allowed") or value.get("deny"):
            active_filters[key] = value
    if active_filters:
        text += ( f" Metadata visibility filters: " f"{active_filters}." )
    return text

# ============================================================================
# Main
# ============================================================================

def llm_explain( rule, example_index, data_mesh_structure, security_groups, available_actions, is_local, n=3, chat_url=None, embedding_url=None, client=None, model=None, embedding_model=None ):
    if not isinstance(rule, str) or not rule.strip():
        raise ValueError( "The rule must be a non-empty string." )
    rule = rule.strip()

    # ------------------------------------------------------------------
    # Normalize authoritative Data Mesh once.
    # ------------------------------------------------------------------
    data_mesh_structure = _normalize_data_mesh_structure( data_mesh_structure )
    security_groups = [ group for group in ( security_groups if isinstance(security_groups, list) else [] ) if isinstance(group, str) and group.strip() ]
    available_actions = _normalize_available_actions( available_actions )

    # ------------------------------------------------------------------
    # Examples
    # ------------------------------------------------------------------

    examples = []
    if example_index:
        examples = find_best_examples( rule=rule, index=example_index, is_local=is_local, n=n, embedding_url=embedding_url, client=client, embedding_model=embedding_model )

    # ------------------------------------------------------------------
    # Security group
    # ------------------------------------------------------------------
    if is_local:
        security_group_result = _extract_security_group_local( rule=rule, security_groups=security_groups, is_local=is_local, chat_url=chat_url, client=client, model=model )
    else:
        security_group_result = _extract_security_group(rule=rule, security_groups=security_groups, is_local=is_local, chat_url=chat_url, client=client, model=model)
    # ------------------------------------------------------------------
    # Resource
    # ------------------------------------------------------------------
    resource = _extract_resource( rule=rule, data_mesh_structure=data_mesh_structure, is_local=is_local, chat_url=chat_url, client=client, model=model )

    # ------------------------------------------------------------------
    # Validate resource
    # ------------------------------------------------------------------
    path_result = _validate_resource_path( resource=resource, data_mesh_structure=data_mesh_structure )

    # ------------------------------------------------------------------
    # Expand only after successful validation.
    # ------------------------------------------------------------------
    expanded_resources = []

    if path_result["valid"]:
        expanded_resources = _expand_resource( resource=resource, data_mesh_structure=data_mesh_structure )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    requested_actions = _extract_actions( rule=rule, available_actions=available_actions, is_local=is_local, chat_url=chat_url, client=client, model=model, examples=examples )

    # --------------------------------------------------------------
    # Metadata visibility restrictions are NOT denied SHOW actions.
    # --------------------------------------------------------------
    if _is_metadata_visibility_restriction(rule):
        requested_actions = []
    print( "[DEBUG] Raw requested_actions:", json.dumps( requested_actions, indent=2, ensure_ascii=False ) )
    requested_actions = _normalize_extracted_actions( requested_actions=requested_actions, available_actions=available_actions )
    print( "[DEBUG] Normalized requested_actions:", json.dumps( requested_actions, indent=2, ensure_ascii=False ) )
    action_result = _validate_actions( requested_actions=requested_actions, available_actions=available_actions )
    allowed, deny, conflicts = _split_allowed_deny( requested_actions, available_actions )

    # ------------------------------------------------------------------
    # Row filter / column mask / metadata visibility
    # ------------------------------------------------------------------
    is_metadata_visibility = _is_metadata_visibility_restriction(rule)

    if not path_result["valid"]:
        effects = { "row_filter": None, "column_masks": {} }
        visibility_filters = { "FilterCatalogs": { "allowed": [], "deny": [] }, "FilterSchemas": { "allowed": [], "deny": [] }, "FilterTables": { "allowed": [], "deny": [] }, "FilterColumns": { "allowed": [], "deny": [] } }

    elif is_metadata_visibility:
        effects = { "row_filter": None, "column_masks": {} }
        visibility_filters = _extract_visibility_filters( rule=rule, resource=resource, data_mesh_structure=data_mesh_structure, is_local=is_local, chat_url=chat_url, client=client, model=model )

    else:
        effects = _extract_effects( rule=rule, resource=resource, data_mesh_structure=data_mesh_structure, is_local=is_local, chat_url=chat_url, client=client, model=model )
        visibility_filters = _extract_visibility_filters( rule=rule, resource=resource, data_mesh_structure=data_mesh_structure, is_local=is_local, chat_url=chat_url, client=client, model=model )

    # ==============================================================
    # Column mask has absolute priority over FilterColumns.
    #
    # If the rule describes values being masked/transformed,
    # the column remains visible and must NEVER become a
    # metadata visibility filter.
    # ==============================================================
    if _is_column_mask_declaration(rule):
        visibility_filters["FilterColumns"] = { "allowed": [], "deny": [] }
    effects_result = _validate_effects( effects=effects, resource=resource, data_mesh_structure=data_mesh_structure )
    visibility_filters_result = _validate_visibility_filters( filters=visibility_filters, resource=resource, data_mesh_structure=data_mesh_structure )

    # ------------------------------------------------------------------
    # Feedback
    # ------------------------------------------------------------------
    feedback = []
    for part in ( security_group_result, path_result, action_result, effects_result, visibility_filters_result ):
        if part.get("feedback"):
            feedback.append( part["feedback"] )
    if conflicts:
        feedback.append( "The same action is both allowed and denied: " + ", ".join( repr(x) for x in conflicts ) + "." )
    resource_was_requested = any( resource.get(field) for field in RESOURCE_FIELDS )
    if ( path_result["valid"] and resource_was_requested and not expanded_resources ):
        feedback.append( "The requested resource path is valid syntactically, " "but it does not resolve to any concrete table or " "column in the Data Mesh Structure." )

    # ------------------------------------------------------------------
    # Important:
    #
    # If the LLM returned an unsupported canonical action, the
    # normalization step intentionally leaves action=None.
    #
    # _validate_actions() then produces feedback.
    #
    # This prevents unsupported operations from silently becoming
    # permissions.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Final explanation
    # ------------------------------------------------------------------

    text =  _build_explanation_text(
        rule=rule,
        group=security_group_result.get("security_group"),
        resource=resource,
        allowed=allowed,
        deny=deny,
        column_masks=effects.get("column_masks", {}),
        row_filter=effects.get("row_filter"),
        visibility_filters=visibility_filters
    )

    # ------------------------------------------------------------------
    # Return
    # ------------------------------------------------------------------

    rewritten_rule = {
        "text": text,
        "securityGroup": security_group_result[ "security_group" ],
        "existSecureGroup": security_group_result[ "existSecureGroup" ],
        "pathExistOnDataMeshStructure": path_result[ "valid" ],
        "actionExist": ( action_result["valid"] and not conflicts ),
        "resource": { "catalog": resource.get("catalog") or "", "schema": resource.get("schema") or "", "table": resource.get("table") or "", "column": resource.get("column") or "" },
        "allowed": allowed,
        "deny": deny,
        "row_filter": effects.get( "row_filter" ),
        "column_masks": effects.get( "column_masks", {} ),
        "FilterCatalogs": visibility_filters.get( "FilterCatalogs", {"allowed": [], "deny": []} ),
        "FilterSchemas": visibility_filters.get( "FilterSchemas", {"allowed": [], "deny": []} ),
        "FilterTables": visibility_filters.get( "FilterTables", {"allowed": [], "deny": []} ),
        "FilterColumns": visibility_filters.get( "FilterColumns", {"allowed": [], "deny": []} ),
        "expandedResources": expanded_resources,
        "llm_feedback": " ".join(feedback)
    }
    with REWRITTEN_RULE_PATH.open( "w", encoding="utf-8" ) as f:
        json.dump( rewritten_rule, f, indent=4, ensure_ascii=False )
    return rewritten_rule
