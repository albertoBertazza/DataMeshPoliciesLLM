package trino.authz

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := true

##################### BATCH #######################


# ------------------------------------------------------------
# Admin: FilterColumns returns every column index.
# ------------------------------------------------------------

batch contains i if {
    input.action.operation == "FilterColumns"

    some i
    input.action.filterResources[0].table.columns[i]
}


# ------------------------------------------------------------
# Admin: other batch operations return every resource index.
# ------------------------------------------------------------

batch contains i if {
    input.action.operation != "FilterColumns"

    some i
    input.action.filterResources[i]
}