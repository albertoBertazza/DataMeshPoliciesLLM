package trino.authz

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false

############ ROLES ############

is_admin if {
    input.context.identity.user == "trino"
}

is_test if {
    input.context.identity.user == "test_access"
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
batchColumnMasks contains {
    "index": i,
    "viewExpression": {
        "expression": "'REDACTED'"
    }
} if {
    some i
    not is_admin

    column_resource := input.action.filterResources[i].column

    column_resource.catalogName == "iceberg"
    column_resource.schemaName == "hr"
    column_resource.tableName == "employees"
    column_resource.columnName == "attrition"
}


batchColumnMasks contains {
    "index": i,
    "viewExpression": {
        "expression": "'******' || substr(businesstravel,7)"
    }
} if {
    some i
    not is_admin

    column_resource := input.action.filterResources[i].column

    column_resource.catalogName == "iceberg"
    column_resource.schemaName == "hr"
    column_resource.tableName == "employees"
    column_resource.columnName == "businesstravel"
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

# Operations that are always blocked regardless of user
#blocked_operations := {
#    "CreateSchema",
#    "CreateTable",
#    "CreateView",
#    "CreateMaterializedView",
#    "DropSchema",
#    "DropTable",
#    "DropView",
#    "RenameTable",
#    "InsertIntoTable",
#    "DeleteFromTable",
#    "TruncateTable"
#}