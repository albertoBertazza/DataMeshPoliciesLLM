package trino.authz

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false

############ input.action.operation #########
#operation := {
#    "ExecuteQuery",
#    "KillQuery",
#    "SelectFromColumns",
#    "GetColumnMask",
#    "GetRowFilters",
#    "ShowTables",
#    "CreateTable",
#    "DropTable",
#    "AlterTable",
#    "InsertIntoTable",
#    "DeleteFromTable",
#    "AccessCatalog",
#    "ShowSchemas",
#    "AccessSchema"
#}

############ ROLES ############

is_admin if {
    input.context.identity.user == "trino"
}

is_test if {
    input.context.identity.user == "test_access"
}

# EXAMPLE OF ROLE ACCESS CONTROL ON HUMAN RESOURCES
# ============================================================
# ROLE DEFINITION
# ============================================================

# analyst_operation groups the three operations that Trino fires
# during every SELECT query:
#   - SelectFromColumns : checks if the user can read those columns
#   - GetColumnMask     : asks OPA if any column should be masked
#   - GetRowFilters     : asks OPA if any row-level filter applies
# These are kept separate from navigation ops because they carry
# resource.table (not resource.catalog or resource.schema).
analyst_operation := {
    "SelectFromColumns",
    "GetColumnMask",
    "GetRowFilters"
}
# define the hr groups
is_hr if {
    "hr_managers" in input.context.identity.groups
}

# ============================================================
# 1. QUERY EXECUTION
# ============================================================

# ExecuteQuery is fired before any SQL is planned — it carries
# no resource at all. It must be allowed standalone, otherwise
# every query is denied before Trino even inspects the tables.
allow if {
    is_hr
    input.action.operation == "ExecuteQuery"
}

# ============================================================
# 2. CATALOG ACCESS
# ============================================================

# AccessCatalog is the hard gate: Trino checks this before
# allowing any interaction with the catalog. Denying it produces
# an explicit "Access Denied" error.
allow if {
    is_hr
    input.action.operation == "AccessCatalog"
    input.action.resource.catalog.name == "iceberg"
}

# FilterCatalogs is the soft gate: Trino calls this when building
# result sets for SHOW CATALOGS. Denying it silently hides the
# catalog from listings without producing an error. Both
# AccessCatalog and FilterCatalogs are needed — one for hard
# access control, one for visibility in listings.
allow if {
    is_hr
    input.action.operation == "FilterCatalogs"
    input.action.resource.catalog.name == "iceberg"
}

# ============================================================
# 3. SCHEMA NAVIGATION
# ============================================================

# ShowSchemas is the hard gate for SHOW SCHEMAS FROM iceberg.
# Note: resource here is resource.catalog (the parent level),
# not resource.schema — Trino hasn't resolved the schema yet.
allow if {
    is_hr
    input.action.operation == "ShowSchemas"
    input.action.resource.catalog.name == "iceberg"
}

# FilterSchemas is the soft gate called per-schema to decide
# what appears in SHOW SCHEMAS results. By allowing only "hr"
# here, alice sees only the hr schema in listings even though
# other schemas exist. Other schemas are silently hidden.
allow if {
    is_hr
    input.action.operation == "FilterSchemas"
    input.action.resource.schema.catalogName == "iceberg"
    input.action.resource.schema.schemaName == "hr"
}

# AccessSchema is required when Trino resolves a schema reference
# in a query (e.g. USE iceberg.hr or any query targeting hr).
# information_schema also needs this because SHOW TABLES, SHOW
# COLUMNS, and DESCRIBE all internally query information_schema.
allow if {
    is_hr
    input.action.operation == "AccessSchema"
    input.action.resource.schema.catalogName == "iceberg"
    input.action.resource.schema.schemaName in {"hr", "information_schema"}
}

# SelectFromColumns on information_schema is needed because SHOW
# TABLES / SHOW COLUMNS / DESCRIBE are rewritten internally by
# Trino as SELECT queries against information_schema system
# tables (e.g. information_schema.tables, .columns). Without
# this, those commands return "Access Denied: Cannot select
# from columns" even if ShowTables is allowed.
allow if {
    is_hr
    input.action.operation == "SelectFromColumns"
    input.action.resource.table.catalogName == "iceberg"
    input.action.resource.table.schemaName == "information_schema"
}

# ============================================================
# 4. TABLE LISTING
# ============================================================

# ShowTables is the hard gate for SHOW TABLES FROM iceberg.hr.
# resource here is resource.schema (the parent level of tables).
# Scoped to hr only — alice cannot list tables in other schemas.
allow if {
    is_hr
    input.action.operation == "ShowTables"
    input.action.resource.schema.catalogName == "iceberg"
    input.action.resource.schema.schemaName == "hr"
}

# FilterTables is the soft gate called per-table when building
# the SHOW TABLES result set. Without this, ShowTables succeeds
# but returns 0 rows because every table is silently filtered
# out. resource here is resource.table (the table's own level).
allow if {
    is_hr
    input.action.operation == "FilterTables"
    input.action.resource.table.catalogName == "iceberg"
    input.action.resource.table.schemaName == "hr"
}

# ============================================================
# 5. DATA ACCESS
# ============================================================

# These three operations are fired for every SELECT query.
# They all carry resource.table, so a single rule covers them.
# Scoped strictly to iceberg.hr — alice cannot read data from
# any other schema even if she can navigate to it.
#
# SelectFromColumns : column-level read authorization
# GetColumnMask     : column masking expression lookup
# GetRowFilters     : row-level filter expression lookup
allow if {
    is_hr
    input.action.operation in analyst_operation
    input.action.resource.table.catalogName == "iceberg"
    input.action.resource.table.schemaName == "hr"
}

############ ALLOW ############

allow if is_admin
allow if is_test

############ ROW FILTERS (SELECT ONLY) ############
table_resource := input.action.resource.table
# we avoid to get rows with attrition='Yes' in iceberg.hr.employees table
rowFilters contains {"expression": "trim(attrition) <> 'Yes'"} if {
  not is_admin
  table_resource.catalogName == "iceberg"
  table_resource.schemaName == "hr"
  table_resource.tableName == "employees"
}

############ COLUMN MASKS ############
# --- MASK passenger_count ---
columnMask := {"expression": "0"} if {
    not is_admin
    input.action.resource.column.catalogName == "iceberg"
    input.action.resource.column.schemaName  == "mobility"
    input.action.resource.column.tableName   == "taxi_trips"
    input.action.resource.column.columnName  == "passenger_count"
}

# --- MASK datetime ---
columnMask := {"expression": "date_trunc('day', tpep_dropoff_datetime)"} if {
    not is_admin
    input.action.resource.column.catalogName == "iceberg"
    input.action.resource.column.schemaName  == "mobility"
    input.action.resource.column.tableName   == "taxi_trips"
    input.action.resource.column.columnName  == "tpep_dropoff_datetime"
}

##########BATCH COLUMN MASKING############
# mask more than 1 column improving performance
# hide attrition value and businesstravel mask: Travel_Frequently to *******_Frequently
batchColumnMasks contains mask if {
    some i
    not is_admin

    column_resource := input.action.filterResources[i].column

    column_resource.catalogName == "iceberg"
    column_resource.schemaName == "hr"
    column_resource.tableName == "employees"
    column_resource.columnName == "attrition"

    mask := {
        "index": i,
        "viewExpression": {
            "expression": "'REDACTED'"
        }
    }
}


batchColumnMasks contains mask if {
    some i
    not is_admin


    column_resource := input.action.filterResources[i].column

    column_resource.catalogName == "iceberg"
    column_resource.schemaName == "hr"
    column_resource.tableName == "employees"
    column_resource.columnName == "businesstravel"

    mask := {
        "index": i,
        "viewExpression": {
            "expression": "'******' || substr(businesstravel,7)"
        }
    }
}


##################### BATCH #######################
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
}
