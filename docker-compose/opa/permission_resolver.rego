package trino.authz

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false

resource_depth := {
    "root": 0,
    "catalog": 1,
    "schema": 2,
    "table": 3,
    "column": 4
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
    res.catalogName != null
} else := {"res": {}, "depth": 0}


# ------------------------------------------------------------
# Scope matching
# ------------------------------------------------------------

scope_matches("root", scope, _) if {
    scope.catalog == null
    scope.schema == null
    scope.table == null
    scope.column == null
}

scope_matches("catalog", scope, res) if {
    scope.catalog == res.catalogName
}

scope_matches("schema", scope, res) if {
    scope.catalog == res.catalogName
    scope.schema == res.schemaName
}

scope_matches("table", scope, res) if {
    scope.catalog == res.catalogName
    scope.schema == res.schemaName
    scope.table == res.tableName
}

scope_matches("column", scope, res) if {
    scope.catalog == res.catalogName
    scope.schema == res.schemaName
    scope.table == res.tableName
    scope.column == res.columnName
}


# ------------------------------------------------------------
# Matching rules
# ------------------------------------------------------------

rule_matches(rule, target_res, target_depth, user_groups) if {
    rule.group in user_groups

    rule_d := resource_depth[rule.resource_type]

    rule_d <= target_depth

    scope_matches(
        rule.resource_type,
        rule.scope,
        target_res
    )
}

matching_rules contains rule if {
    some rule in data.rules

    info := target_info

    rule_matches(
        rule,
        info.res,
        info.depth,
        input.context.identity.groups
    )
}


# ------------------------------------------------------------
# Most-specific permission declaration
# ------------------------------------------------------------

permission_rules(perm) := rules if {
    rules := [
        r |
        some r in matching_rules
        perm in r.permissions.allow
        resource_depth[r.resource_type] <= target_info.depth
    ]
}

deny_rules(perm) := rules if {
    rules := [
        r |
        some r in matching_rules
        perm in r.permissions.deny
        resource_depth[r.resource_type] <= target_info.depth
    ]
}


# ------------------------------------------------------------
# Find the most-specific declaration
# ------------------------------------------------------------

most_specific_permission_rule(perm) := rule if {
    candidates := [
        r |
        some r in matching_rules
        perm in r.permissions.allow
        resource_depth[r.resource_type] <= target_info.depth
    ]

    count(candidates) > 0

    max_depth := max([
        resource_depth[r.resource_type] |
        some r in candidates
    ])

    some r in candidates
    resource_depth[r.resource_type] == max_depth

    rule := r
}

most_specific_deny_rule(perm) := rule if {
    candidates := [
        r |
        some r in matching_rules
        perm in r.permissions.deny
        resource_depth[r.resource_type] <= target_info.depth
    ]

    count(candidates) > 0

    max_depth := max([
        resource_depth[r.resource_type] |
        some r in candidates
    ])

    some r in candidates
    resource_depth[r.resource_type] == max_depth

    rule := r
}


# ------------------------------------------------------------
# Effective permission
#
# Most-specific explicit declaration wins.
# If there is no declaration, permission is denied.
# ------------------------------------------------------------

permission_allowed(perm) if {
    allow_rule := most_specific_permission_rule(perm)

    not most_specific_deny_rule_at_same_depth(perm, allow_rule)
}

permission_allowed(perm) if {
    deny_rule := most_specific_deny_rule(perm)

    not most_specific_allow_rule_at_same_depth(perm, deny_rule)

    # This rule is currently a deny, so this branch
    # intentionally does not grant the permission.
    false
}


most_specific_deny_rule_at_same_depth(perm, allow_rule) if {
    deny_rule := most_specific_deny_rule(perm)

    resource_depth[deny_rule.resource_type] ==
    resource_depth[allow_rule.resource_type]
}

most_specific_allow_rule_at_same_depth(perm, deny_rule) if {
    allow_rule := most_specific_permission_rule(perm)

    resource_depth[allow_rule.resource_type] ==
    resource_depth[deny_rule.resource_type]
}


# ------------------------------------------------------------
# Action authorization
# ------------------------------------------------------------

allow if {
    permission_allowed(input.action.operation)
}


# ------------------------------------------------------------
# ADMIN
# ------------------------------------------------------------

is_admin if {
    "admin" in input.context.identity.groups
}

allow if is_admin


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
        r |
        some r in data.rules

        r.group in input.context.identity.groups
        r.column_masks[column_resource.columnName] != null

        rule_matches(
            r,
            column_resource,
            4,
            input.context.identity.groups
        )
    ]

    count(masking_rules) > 0

    max_d := max([
        resource_depth[r.resource_type] |
        some r in masking_rules
    ])

    some r in masking_rules
    resource_depth[r.resource_type] == max_d

    mask := {
        "index": i,
        "viewExpression": {
            "expression": r.column_masks[column_resource.columnName]
        }
    }
}


##################### BATCH #######################

# Admin: FilterColumns returns every column index.
batch contains i if {
    is_admin
    input.action.operation == "FilterColumns"

    some i
    input.action.filterResources[0].table.columns[i]
}

# Admin: other batch operations return every resource index.
batch contains i if {
    is_admin
    input.action.operation != "FilterColumns"

    some i
    input.action.filterResources[i]
}

# FilterCatalogs:
# Trino sends catalog.name, while the policy resolver expects catalogName.
batch contains i if {
    not is_admin
    input.action.operation == "FilterCatalogs"
    some i

    raw_resource := input.action.filterResources[i]

    allow
        with input.action.operation as "AccessCatalog"
        with input.action.resource as {
            "catalog": {
                "catalogName": raw_resource.catalog.name
            }
        }
}

# Normal batch authorization.
batch contains i if {
    not is_admin
    input.action.operation != "FilterCatalogs"

    some i

    raw_resource := input.action.filterResources[i]

    allow with input.action.resource as raw_resource
}

# FilterColumns special case.
batch contains i if {
    not is_admin
    input.action.operation == "FilterColumns"
    count(input.action.filterResources) == 1

    raw_resource := input.action.filterResources[0]
    column_name := raw_resource.table.columns[i]

    allow with input.action.operation as "SelectFromColumns" with input.action.resource as {
        "column": {
            "catalogName": raw_resource.table.catalogName,
            "schemaName": raw_resource.table.schemaName,
            "tableName": raw_resource.table.tableName,
            "columnName": column_name
        }
    }
}