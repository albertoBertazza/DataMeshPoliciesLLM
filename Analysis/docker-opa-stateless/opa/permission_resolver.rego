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
#
# Example:
#
# root
# root/iceberg
# root/iceberg/hr
# root/iceberg/hr/people
# root/iceberg/hr/people/email
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
#
# data.rules is now:
#
# {
#   "root": {
#       "hr_manager": {...}
#   },
#   "root/iceberg": {
#       "hr_manager": {...}
#   }
# }
#
# A rule matches when:
#   1. its resource path is an ancestor of the target
#   2. its group belongs to the user
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
#
# A path is an ancestor when:
#
# root
# root/iceberg
# root/iceberg/hr
# root/iceberg/hr/people
#
# are prefixes of the target path.
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
#
# Current semantics:
#
# ALLOW if an applicable rule grants the permission
# and no applicable rule denies it.
#
# Therefore a DENY anywhere on the target path
# overrides an ALLOW.
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

allow if {
    permission_allowed(input.action.operation)
}

allow if {
    is_admin
}


# ------------------------------------------------------------
# Row filters
#
# All matching row filters are returned.
# Trino combines returned row filters conjunctively.
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
#
# Most-specific matching rule wins for each column.
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


##################### BATCH #######################


# ------------------------------------------------------------
# Admin: FilterColumns returns every column index.
# ------------------------------------------------------------

batch contains i if {
    is_admin
    input.action.operation == "FilterColumns"

    some i
    input.action.filterResources[0].table.columns[i]
}


# ------------------------------------------------------------
# Admin: other batch operations return every resource index.
# ------------------------------------------------------------

batch contains i if {
    is_admin
    input.action.operation != "FilterColumns"

    some i
    input.action.filterResources[i]
}


# ------------------------------------------------------------
# FilterCatalogs
# ------------------------------------------------------------

batch contains i if {
    not is_admin
    input.action.operation == "FilterCatalogs"
    some i

    raw_resource := input.action.filterResources[i]

    allow
        with input.action.operation as "AccessCatalog"
        with input.action.resource as {
            "catalog": {
                "name": raw_resource.catalog.name
            }
        }
}


# ------------------------------------------------------------
# FilterSchemas -> ShowSchemas
# ------------------------------------------------------------

batch contains i if {
    not is_admin
    input.action.operation == "FilterSchemas"

    some i
    raw_resource := input.action.filterResources[i]

    # A schema is visible when ShowSchemas is allowed
    # on that schema.
    allow
        with input.action.operation as "ShowSchemas"
        with input.action.resource as raw_resource
}

# ------------------------------------------------------------
# FilterTables -> ShowTables
# ------------------------------------------------------------
batch contains i if {
    not is_admin
    input.action.operation == "FilterTables"

    some i
    raw_resource := input.action.filterResources[i]

    allow
        with input.action.operation as "ShowTables"
        with input.action.resource as raw_resource
}


# ------------------------------------------------------------
# Normal batch authorization
# ------------------------------------------------------------

batch contains i if {
    not is_admin

    input.action.operation != "FilterCatalogs"
    input.action.operation != "FilterSchemas"
    input.action.operation != "FilterTables"

    some i

    raw_resource := input.action.filterResources[i]

    allow with input.action.resource as raw_resource
}


# ------------------------------------------------------------
# FilterColumns
# ------------------------------------------------------------

batch contains i if {
    not is_admin
    input.action.operation == "FilterColumns"
    count(input.action.filterResources) == 1

    raw_resource := input.action.filterResources[0]
    column_name := raw_resource.table.columns[i]

    allow
        with input.action.operation as "SelectFromColumns"
        with input.action.resource as {
            "column": {
                "catalogName": raw_resource.table.catalogName,
                "schemaName": raw_resource.table.schemaName,
                "tableName": raw_resource.table.tableName,
                "columnName": column_name
            }
        }
}

#debug_target := {
#    "operation": input.action.operation,
#    "target_info": target_info,
#    "target_path": target_path,
#    "matching_rules": [r | r := matching_rules[_]]
#}