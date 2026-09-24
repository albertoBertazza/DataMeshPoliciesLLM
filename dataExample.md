Yes. To use the **map representation safely with multiple security groups**, I would use:

```text
rules
  → resource path
      → security group
          → rule
```

So the structure becomes:

```json
{
  "rules": {
    "root": {
      "hr_manager": {
        
      },
      "auditor": {
        
      }
    },
    "root/iceberg": {
      "hr_manager": {
        
      }
    }
  }
}
```

This avoids the duplicate-key problem when two groups have rules for the same resource.

The Rego then needs to stop using `rule.scope`, because the **resource path is now the map key**.

Here is the corrected version.

```rego
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
    res.catalogName != null
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
    [target_info.res.catalogName]
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
                "catalogName": raw_resource.catalog.name
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
```

### Corresponding `data.json`

Your HR example should now become:

```json
{
  "version": "2.0-opa",
  "rules": {
    "root": {
      "hr_manager": {
        "rule_id": "rule_root_hr",
        "group": "hr_manager",
        "resource_type": "root",
        "permissions": {
          "allow": [
            "AccessCatalog",
            "ExecuteQuery"
          ],
          "deny": []
        },
        "row_filter": null,
        "column_masks": {}
      }
    },

    "root/iceberg": {
      "hr_manager": {
        "rule_id": "rule_catalog_iceberg_hr",
        "group": "hr_manager",
        "resource_type": "catalog",
        "permissions": {
          "allow": [
            "ExecuteQuery",
            "SelectFromColumns",
            "GetRowFilters",
            "GetColumnMask",
            "InsertTable"
          ],
          "deny": []
        },
        "row_filter": "job_title = 'Biochemist, clinical'",
        "column_masks": {}
      }
    },

    "root/iceberg/hr/people": {
      "hr_manager": {
        "rule_id": "rule_table_people",
        "group": "hr_manager",
        "resource_type": "table",
        "permissions": {
          "allow": [],
          "deny": [
            "InsertTable"
          ]
        },
        "row_filter": null,
        "column_masks": {}
      }
    },

    "root/iceberg/hr/people/email": {
      "hr_manager": {
        "rule_id": "rule_column_people_email",
        "group": "hr_manager",
        "resource_type": "column",
        "permissions": {
          "allow": [],
          "deny": []
        },
        "row_filter": null,
        "column_masks": {
          "email": "'****' || substring(email, -4)"
        }
      }
    }
  }
}
```



### One important correction

Your old Rego used:

```rego
scope_matches(...)
```

because every rule contained a `scope`.

With the map representation, that is unnecessary:

```text
"root/iceberg/hr/people"
```

**is the scope.**

So the model becomes much simpler:

```text
rules
│
├── root
│   ├── hr_manager → rule
│   └── auditor    → rule
│
├── root/iceberg
│   └── hr_manager → rule
│
└── root/iceberg/hr/people
    └── hr_manager → rule
```

This also solves the biggest problem with a flat `resource_path → rule` map: **multiple groups can now have independent rules for the same resource.**

One further point: the `permission_allowed()` above preserves your **current Rego semantics** where *any matching deny overrides an allow*. If your final model is the newer **most-specific explicit declaration wins** semantics, that function should be changed separately; the map representation itself does not prevent that model.

### SQL tests

```bash
bash Communication/trino_session.sh --user hr --password hr123
```

For your current permission-based model, use these:


```sql
-- ============================================================
-- 1. SELECT
-- ============================================================
-- Expected:
--   SelectFromColumns  -> ALLOW
--   GetRowFilters      -> ALLOW
--   GetColumnMask      -> ALLOW
--
-- The row filter should be applied:
--   job_title = 'HR'
--
    
-- YOU will get 3 rows because of row filter.
-- ============================================================

SELECT *
FROM iceberg.hr.people;


-- ============================================================
-- 2. SELECT EMAIL
-- ============================================================
-- Expected:
--   SelectFromColumns -> ALLOW
--   GetColumnMask     -> ALLOW
--
-- email should be masked according to:
--   '****' || substring(email, -4)
--
-- ============================================================

SELECT
    first_name,
    last_name,
    email
FROM iceberg.hr.people
LIMIT 5;


-- ============================================================
-- 3. SELECT WITHOUT EMAIL
-- ============================================================
-- Expected: ALLOW
--
-- This is useful to verify normal columns are accessible.
-- i will get 3 rows because of row filter.
-- ============================================================

SELECT
    employee_index,
    user_id,
    first_name,
    last_name,
    job_title
FROM iceberg.hr.people
LIMIT 5;


-- ============================================================
-- 4. INSERT
-- ============================================================
-- Expected: DENY
--
-- Catalog:
--   InsertTable -> ALLOW
--
-- Table:
--   InsertTable -> DENY
--
-- The table-level DENY is more specific and therefore wins.
-- ============================================================

INSERT INTO iceberg.hr.people
    (employee_index, user_id, first_name, last_name, job_title)
VALUES
    (100, 'u100', 'John', 'Smith', 'Developer');


-- ============================================================
-- 5. UPDATE
-- ============================================================
-- Expected: DENY
--
-- UpdateTableColumns is not granted anywhere.
-- ============================================================

UPDATE iceberg.hr.people
SET first_name = 'Jane'
WHERE employee_index = 1;


-- ============================================================
-- 6. DELETE
-- ============================================================
-- Expected: DENY
--
-- DeleteFromTable is not granted anywhere.
-- ============================================================

DELETE FROM iceberg.hr.people
WHERE employee_index = 1;


-- ============================================================
-- 7. CREATE TABLE
-- ============================================================
-- Expected: DENY
--
-- CreateTable is not granted.
-- ============================================================

CREATE TABLE iceberg.hr.test_table (
    id INTEGER
);


-- ============================================================
-- 8. DROP TABLE
-- ============================================================
-- Expected: DENY
--
-- DropTable is not granted.
-- ============================================================

DROP TABLE iceberg.hr.people;


-- ============================================================
-- 9. TRUNCATE
-- ============================================================
-- Expected: DENY
--
-- TruncateTable is not granted.
-- ============================================================

TRUNCATE TABLE iceberg.hr.people;
```

### The important permission results

For `hr_manager` and `iceberg.hr.people`, your resolver should produce:

| Permission           | Result    | Reason                           |
| -------------------- | --------- | -------------------------------- |
| `AccessCatalog`      | **ALLOW** | root                             |
| `ExecuteQuery`       | **ALLOW** | `iceberg` catalog                |
| `SelectFromColumns`  | **ALLOW** | `iceberg` catalog                |
| `GetRowFilters`      | **ALLOW** | `iceberg` catalog                |
| `GetColumnMask`      | **ALLOW** | `iceberg` catalog                |
| `InsertTable`        | **DENY**  | `people` table overrides catalog |
| `UpdateTableColumns` | **DENY**  | no declaration                   |
| `DeleteFromTable`    | **DENY**  | no declaration                   |
| `CreateTable`        | **DENY**  | no declaration                   |
| `DropTable`          | **DENY**  | no declaration                   |
| `TruncateTable`      | **DENY**  | no declaration                   |

And this is the key hierarchy test:

```text
iceberg
└── InsertTable = ALLOW

iceberg.hr.people
└── InsertTable = DENY

        ↓

effective InsertTable = DENY
```

For the email column:

```text
iceberg
└── GetColumnMask = ALLOW

iceberg.hr.people.email
└── column_masks.email = "'****' || substring(email, -4)"
```

So the policy is now internally consistent with your actual Data Mesh.

**One caveat:** `SELECT` itself may trigger several Trino authorization checks rather than one single OPA call. That's why testing the individual permissions (`SelectFromColumns`, `GetRowFilters`, `GetColumnMask`, etc.) is useful when debugging your OPA policy.

And your **auditor full-access rule** becomes simply:

```json
{
  "version": "2.0-opa",
  "rules": {
    "root": {
      "auditor": {
        "rule_id": "rule_root_auditor",
        "group": "auditor",
        "resource_type": "root",
        "permissions": {
          "allow": [
            "AccessCatalog",
            "AddColumn",
            "CreateMaterializedView",
            "CreateSchema",
            "CreateTable",
            "CreateView",
            "DeleteFromTable",
            "DropColumn",
            "DropMaterializedView",
            "DropSchema",
            "DropTable",
            "DropView",
            "ExecuteQuery",
            "GetColumnMask",
            "GetRowFilters",
            "InsertIntoTable",
            "RefreshMaterializedView",
            "RenameColumn",
            "RenameMaterializedView",
            "RenameTable",
            "RenameView",
            "SelectFromColumns",
            "SetColumnComment",
            "SetTableComment",
            "SetViewComment",
            "ShowColumns",
            "ShowCreateSchema",
            "ShowCreateTable",
            "ShowSchemas",
            "ShowTables",
            "TruncateTable",
            "UpdateTableColumns"
          ],
          "deny": []
        },
        "row_filter": null,
        "column_masks": {}
      }
    }
  }
}
```