package trino

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





target_info := {"res": res, "depth": depth} if {
    res := input.action.resource.column
    res.columnName != null
    depth := 4
} else := {"res": res, "depth": depth} if {
    res := input.action.resource.table
    res.tableName != null
    depth := 3
} else := {"res": res, "depth": depth} if {
    res := input.action.resource.schema
    res.schemaName != null
    depth := 2
} else := {"res": res, "depth": depth} if {
    res := input.action.resource.catalog
    res.catalogName != null
    depth := 1
} else := {"res": {}, "depth": 0}



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





rule_matches(rule, target_res, target_depth, user_groups) if {
    rule.group in user_groups
    rule_d := resource_depth[rule.resource_type]
    rule_d <= target_depth
    scope_matches(rule.resource_type,rule.scope,target_res)
}

matching_rules contains rule if {
    some rule in data.rules
    info := target_info
    rule_matches(rule,info.res,info.depth,input.context.identity.groups)
}







permission_denied(perm) if {
    some r in matching_rules
    perm in r.permissions.deny
}

permission_allowed(perm) if {
    not permission_denied(perm)

    some r in matching_rules
    perm in r.permissions.allow
}






allow if {
    permission_allowed(input.action.operation)
}






# ALLOW ALL TO TRINO, i need to create the datamesh so i need all the permission
is_admin if {
    "admin" in input.context.identity.groups
}
allow if is_admin




columnMask := {
    "expression": mask_expr
} if {
    col_name := input.action.resource.column.columnName

    masking_rules:= [ r |
                    some r in matching_rules r.column_masks[col_name]!=null]

    count(masking_rules) > 0

    max_d := max([ resource_depth[r.resource_type] | some r in masking_rules ])

    some r in masking_rules
    resource_depth[r.resource_type] == max_d
    mask_expr := r.column_masks[col_name]
}

rowFilters contains {
    "expression": r.row_filter
} if {
    some r in matching_rules
    r.row_filter != null
}