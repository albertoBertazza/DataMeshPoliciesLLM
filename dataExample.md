### Corrected `data.json`

This version uses only resources/columns that actually exist in your Data Mesh, and uses `job_title` for the row filter.

```json
{
  "version": "2.0-opa",
  "rules": [
    {
      "rule_id": "rule_root_hr",
      "group": "hr_manager",
      "resource_type": "root",
      "scope": {
        "catalog": null,
        "schema": null,
        "table": null,
        "column": null
      },
      "permissions": {
          "allow": ["AccessCatalog", "ExecuteQuery"],
          "deny": []
      },
      "row_filter": null,
      "column_masks": {}
    },
    {
      "rule_id": "rule_catalog_iceberg_hr",
      "group": "hr_manager",
      "resource_type": "catalog",
      "scope": {
        "catalog": "iceberg",
        "schema": null,
        "table": null,
        "column": null
      },
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
    },
    {
      "rule_id": "rule_table_people",
      "group": "hr_manager",
      "resource_type": "table",
      "scope": {
        "catalog": "iceberg",
        "schema": "hr",
        "table": "people",
        "column": null
      },
      "permissions": {
        "allow": [],
        "deny": [
          "InsertTable"
        ]
      },
      "row_filter": null,
      "column_masks": {}
    },
    {
      "rule_id": "rule_column_people_email",
      "group": "hr_manager",
      "resource_type": "column",
      "scope": {
        "catalog": "iceberg",
        "schema": "hr",
        "table": "people",
        "column": "email"
      },
      "permissions": {
        "allow": [],
        "deny": []
      },
      "row_filter": null,
      "column_masks": {
        "email": "'****' || substring(email, -4)"
      }
    }
  ]
}
```

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
