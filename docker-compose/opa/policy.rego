package trino.authz

default allow := false

# Operations that are always blocked regardless of user
blocked_operations := {
    "CreateSchema",
    "CreateTable",
    "CreateView",
    "CreateMaterializedView",
    "DropSchema",
    "DropTable",
    "DropView",
    "RenameTable",
    "InsertIntoTable",
    "DeleteFromTable",
    "TruncateTable"
}

#
# TRINO CLI USER - full access
#
#allow if {
#    input.context.identity.user == "trino"
#}

#
# ANALYST - read only
#
allow if {
    input.context.identity.user == "analyst"
    input.action.operation == "SelectFromColumns"
    input.resource.schema == "sales"
    not blocked_operations[input.action.operation]
}