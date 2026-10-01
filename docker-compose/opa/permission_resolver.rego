package trino.authz

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false

# ------------------------------------------------------------
# Resource depths
# ------------------------------------------------------------

resource_depth := {
    "root": 0,
    "catalog": 1,
    "schema": 2,
    "table": 3,
    "column": 4
}

# ------------------------------------------------------------
# ADMIN
# ------------------------------------------------------------

is_admin if {
    "admin" in input.context.identity.groups
}

# ------------------------------------------------------------
# Target resource
# ------------------------------------------------------------

target_info := {"res": res, "depth": 4} if {
    res := input.action.resource.column
    res.columnName != null
} else := {"res": res, "depth": 3} if {
    res := input.action.resource.table
    res.tableName != null
} else := {"res": res, "depth": 2} if {
    res := input.action.resource.schema
    res.schemaName != null
} else := {"res": res, "depth": 1} if {
    res := input.action.resource.catalog
    res.name != null
} else := {
    "res": {
        "catalogName": null,
        "schemaName": null,
        "tableName": null,
        "columnName": null
    },
    "depth": 0
}

# ------------------------------------------------------------
# Resource path
# ------------------------------------------------------------

target_path := "root" if {
    target_info.depth == 0
} else := sprintf(
    "root/%s",
    [target_info.res.name]
) if {
    target_info.depth == 1
} else := sprintf(
    "root/%s/%s",
    [
        target_info.res.catalogName,
        target_info.res.schemaName
    ]
) if {
    target_info.depth == 2
} else := sprintf(
    "root/%s/%s/%s",
    [
        target_info.res.catalogName,
        target_info.res.schemaName,
        target_info.res.tableName
    ]
) if {
    target_info.depth == 3
} else := sprintf(
    "root/%s/%s/%s/%s",
    [
        target_info.res.catalogName,
        target_info.res.schemaName,
        target_info.res.tableName,
        target_info.res.columnName
    ]
) if {
    target_info.depth == 4
}

# ------------------------------------------------------------
# Matching rules
# ------------------------------------------------------------

matching_rules contains rule if {
    some resource_path, group_rules in data.rules
    some group, rule in group_rules

    group in input.context.identity.groups

    path_is_ancestor(resource_path, target_path)

    rule.group == group
}

# ------------------------------------------------------------
# Path hierarchy
# ------------------------------------------------------------

path_is_ancestor("root", _) if true

path_is_ancestor(path, target) if {
    path != "root"
    startswith(target, sprintf("%s/", [path]))
}

path_is_ancestor(path, target) if {
    path == target
}

# ------------------------------------------------------------
# Effective permission
# ------------------------------------------------------------

permission_denied(perm) if {
    some r in matching_rules
    perm in r.permissions.deny
}

permission_allowed(perm) if {
    some r in matching_rules
    perm in r.permissions.allow

    not permission_denied(perm)
}

# ------------------------------------------------------------
# Action authorization
# ------------------------------------------------------------

is_metadata_filter_operation(operation) if {
    operation in {
        "FilterCatalogs",
        "FilterSchemas",
        "FilterTables",
        "FilterColumns"
    }
}

allow if {
    not is_metadata_filter_operation(input.action.operation)
    permission_allowed(input.action.operation)
}

allow if {
    is_admin
}

# ------------------------------------------------------------
# Row filters
# ------------------------------------------------------------

rowFilters contains {
    "expression": r.row_filter
} if {
    not is_admin

    some r in matching_rules

    r.row_filter != null
}

# ------------------------------------------------------------
# Batch column masking
# ------------------------------------------------------------

batchColumnMasks contains mask if {
    not is_admin

    some i

    column_resource := input.action.filterResources[i].column

    masking_rules := [
        {
            "path": resource_path,
            "rule": r
        } |
        some resource_path, group_rules in data.rules
        some group, r in group_rules

        group in input.context.identity.groups

        r.column_masks[column_resource.columnName] != null

        path_is_ancestor(
            resource_path,
            sprintf(
                "root/%s/%s/%s/%s",
                [
                    column_resource.catalogName,
                    column_resource.schemaName,
                    column_resource.tableName,
                    column_resource.columnName
                ]
            )
        )
    ]

    count(masking_rules) > 0

    max_depth := max([
        path_depth(x.path) |
        some x in masking_rules
    ])

    some x in masking_rules
    path_depth(x.path) == max_depth

    mask := {
        "index": i,
        "viewExpression": {
            "expression": x.rule.column_masks[column_resource.columnName]
        }
    }
}

# ------------------------------------------------------------
# Path depth
# ------------------------------------------------------------

path_depth(path) := 0 if {
    path == "root"
}

path_depth(path) := 1 if {
    count(split(path, "/")) == 2
}

path_depth(path) := 2 if {
    count(split(path, "/")) == 3
}

path_depth(path) := 3 if {
    count(split(path, "/")) == 4
}

path_depth(path) := 4 if {
    count(split(path, "/")) == 5
}

# ============================================================
# BATCH
# ============================================================

# ------------------------------------------------------------
# Admin: FilterColumns returns every column index
# ------------------------------------------------------------

batch contains i if {
    is_admin
    input.action.operation == "FilterColumns"

    some i
    input.action.filterResources[0].table.columns[i]
}

# ------------------------------------------------------------
# Admin: other batch operations return every resource index
# ------------------------------------------------------------

batch contains i if {
    is_admin
    input.action.operation != "FilterColumns"

    some i
    input.action.filterResources[i]
}

# ============================================================
# METADATA DENY LISTS
#
# IMPORTANT:
#
# Filter* entries contain VALUES THAT MUST BE HIDDEN.
#
# Example:
#
# "root/iceberg/hr": {
#     "FilterTables": {
#         "hr_manager": ["salary"]
#     }
# }
#
# means:
#
#   salary -> hidden
#   people -> visible
#   orders -> visible
#
# If the group has no FilterTables entry at this path,
# everything passed in filterResources is visible.
# ============================================================

explicit_filter_denied(
    filter_operation,
    filter_path,
    resource_name
) if {
    path_rules := data.rules[filter_path]
    filter_rules := path_rules[filter_operation]

    some group in input.context.identity.groups

    denied_resources := filter_rules[group]

    resource_name in denied_resources
}

# ============================================================
# FilterCatalogs
# ============================================================

batch contains i if {
    not is_admin
    input.action.operation == "FilterCatalogs"

    some i

    raw_resource := input.action.filterResources[i]

    catalog_name := raw_resource.catalog.name

    not explicit_filter_denied(
        "FilterCatalogs",
        "root",
        catalog_name
    )
}

# ============================================================
# FilterSchemas
# ============================================================

batch contains i if {
    not is_admin
    input.action.operation == "FilterSchemas"

    some i

    raw_resource := input.action.filterResources[i]

    catalog_name := raw_resource.schema.catalogName
    schema_name := raw_resource.schema.schemaName

    filter_path := sprintf(
        "root/%s",
        [catalog_name]
    )

    not explicit_filter_denied(
        "FilterSchemas",
        filter_path,
        schema_name
    )
}

# ============================================================
# FilterTables
# ============================================================

batch contains i if {
    not is_admin
    input.action.operation == "FilterTables"

    some i

    raw_resource := input.action.filterResources[i]

    catalog_name := raw_resource.table.catalogName
    schema_name := raw_resource.table.schemaName
    table_name := raw_resource.table.tableName

    filter_path := sprintf(
        "root/%s/%s",
        [
            catalog_name,
            schema_name
        ]
    )

    not explicit_filter_denied(
        "FilterTables",
        filter_path,
        table_name
    )
}

# ============================================================
# FilterColumns
# ============================================================

batch contains i if {
    not is_admin
    input.action.operation == "FilterColumns"

    count(input.action.filterResources) == 1

    raw_resource := input.action.filterResources[0]

    catalog_name := raw_resource.table.catalogName
    schema_name := raw_resource.table.schemaName
    table_name := raw_resource.table.tableName

    some i

    column_name := raw_resource.table.columns[i]

    filter_path := sprintf(
        "root/%s/%s/%s",
        [
            catalog_name,
            schema_name,
            table_name
        ]
    )

    not explicit_filter_denied(
        "FilterColumns",
        filter_path,
        column_name
    )
}

# ============================================================
# information_schema
# ============================================================

allow if {
    input.action.operation == "SelectFromColumns"
    input.action.resource.table.catalogName == "iceberg"
    input.action.resource.table.schemaName == "information_schema"
}

# ============================================================
# Debug
# ============================================================

debug_filter_tables := {
    "operation": input.action.operation,
    "groups": input.context.identity.groups,
    "filter_path": sprintf(
        "root/%s/%s",
        [
            input.action.filterResources[0].table.catalogName,
            input.action.filterResources[0].table.schemaName
        ]
    ),
    "filter_rules": data.rules[
        sprintf(
            "root/%s/%s",
            [
                input.action.filterResources[0].table.catalogName,
                input.action.filterResources[0].table.schemaName
            ]
        )
    ]["FilterTables"],
    "table": input.action.filterResources[0].table.tableName
}