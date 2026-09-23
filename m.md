Your **resolver is now correct**. The new problem is in the **test generator**.

For `CreateMaterializedViewAction` you have:

* Rule target: `iceberg.hr.people` → **table**
* Authorization resource level for the action: `schema`
* SQL needs the existing table `people` as the source:

```sql
CREATE MATERIALIZED VIEW iceberg.hr.test_materialized_view
AS SELECT * FROM iceberg.hr.people LIMIT 5;
```

Your generator currently does this:

```text
table rule
   ↓
action resource_level = schema
   ↓
resource becomes iceberg/hr
   ↓
table = ""
   ↓
SQL cannot be generated
```

That is exactly why you get:

```text
[TEST SKIP] Cannot generate SQL for action='CreateMaterializedViewAction',
resource={'catalog': 'iceberg', 'schema': 'hr', 'table': '', 'column': ''}
```

### Correct separation

You now need **three different concepts**:

1. **Rule resource** — where the user authorization rule applies
   `root/iceberg/hr/people` → table

2. **Permission resolution** — walks from that resource toward root
   `CreateMaterializedView` is found at `root/iceberg/hr`

3. **SQL resource/context** — what information is needed to construct the SQL
   `CreateMaterializedViewAction` needs `catalog + schema + table`

The `resource_level: "schema"` in the SQL mapping **must not remove the table from the resource**.

So the clean fix is: **remove the resource-level normalization/collapse from the generator.** The resolver already gives exactly one target at the correct rule depth.

---

### Replace `_collapse_resolved_targets()` with this

```python
def _collapse_resolved_targets(
    self,
    resolved_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Keep the resource exactly as resolved by AuthorizationResolver.

    The resolver already returns ONE target at the resource depth
    explicitly expressed by the authorization rule.

    IMPORTANT:
        action_sql_mapping["resource_level"] describes the SQL/
        authorization level of the action. It must NOT be used to
        remove fields from the rule resource.

    Example:

        Rule:
            hr_manager can create materialized view on iceberg.hr.people

        Resolver resource:
            {
                "catalog": "iceberg",
                "schema": "hr",
                "table": "people",
                "column": ""
            }

        CreateMaterializedViewAction:
            resource_level = "schema"

        We still keep "table": "people" because the SQL template
        needs the source table:

            CREATE MATERIALIZED VIEW iceberg.hr.<view>
            AS SELECT * FROM iceberg.hr.people LIMIT 5;

    The resolver is already responsible for producing one result
    per explicit authorization rule target, so no descendant
    expansion or action-level collapsing is necessary here.
    """

    # Remove only exact duplicate resolver targets.
    #
    # This is defensive. Normally the resolver already returns
    # one result per authorization rule.

    unique: Dict[tuple, Dict[str, Any]] = {}

    for authorization in resolved_results:
        resource = authorization.get("resource", {})

        resource_key = (
            authorization.get("securityGroup", ""),
            authorization.get("resourcePath", ""),
            tuple(sorted(resource.items())),
        )

        unique[resource_key] = authorization

    return list(unique.values())
```

Then your debug code should **not** print/use `resource_level` to construct a normalized resource.

Instead of something like:

```python
mapping = self.action_sql_mapping.get(action_name)
resource_level = mapping.get("resource_level")
resource = self._resource_at_level(original_resource, resource_level)
```

use:

```python
resource = dict(authorization.get("resource", {}))

mapping = self.action_sql_mapping.get(action_name, {})
resource_level = mapping.get("resource_level")

print(
    f"[TEST DEBUG] "
    f"group={security_group}, "
    f"users={len(users)}, "
    f"action={action_name}, "
    f"resource_level={resource_level}, "
    f"resource={resource}, "
    f"resourcePath={authorization.get('resourcePath')}"
)
```

Notice that `resource_level` is still printed for information, but **it does not modify `resource`**.

---

### Also remove this transformation

You should no longer use this for resolved authorization targets:

```python
normalized_resource = self._resource_at_level(
    original_resource,
    resource_level,
)
```

or:

```python
resource = self._resource_at_level(
    authorization["resource"],
    mapping["resource_level"],
)
```

That function is what caused:

```python
{
    "catalog": "iceberg",
    "schema": "hr",
    "table": "",
    "column": ""
}
```

---

### What the second rule should produce

Your resolver is already producing:

```json
{
  "resource": {
    "catalog": "iceberg",
    "schema": "hr",
    "table": "people",
    "column": ""
  },
  "resourcePath": "root/iceberg/hr/people",
  "resourceType": "table"
}
```

The generator should pass that unchanged to SQL generation.

Then:

```text
CreateMaterializedViewAction
resource_level = schema
resource =
    catalog = iceberg
    schema  = hr
    table   = people
```

and `_action_to_query()` can generate:

```sql
CREATE MATERIALIZED VIEW iceberg.hr.test_materialized_view
AS SELECT * FROM iceberg.hr.people LIMIT 5;
```

So you should get **2 tests**, one for `hr` and one for `mario`, just like the `CreateSchemaAction` case.

### Expected debug output

It should become approximately:

```text
[TEST DEBUG] Resolver entries: 1
[TEST DEBUG] Test targets after resource-level collapse: 1
[TEST DEBUG] group=hr_manager, users=2, action=CreateMaterializedViewAction, resource_level=schema, resource={'catalog': 'iceberg', 'schema': 'hr', 'table': 'people', 'column': ''}, resourcePath=root/iceberg/hr/people
```

and then:

```text
TEST GENERATION
[
  {
    "securityGroup": "hr_manager",
    "resourcePath": "root/iceberg/hr/people",
    "resource": {
      "catalog": "iceberg",
      "schema": "hr",
      "table": "people",
      "column": ""
    },
    "action": "CreateMaterializedViewAction",
    ...
  },
  {
    ...
  }
]
```

The important architectural point is:

> **`resource_level` in the SQL mapping tells you what the action is authorized against; it does not tell you which resource fields must be deleted before generating SQL.**

For `CreateMaterializedViewAction`, authorization is schema-level, but the SQL still needs a table as its source. Your resolver now preserves exactly the information needed for that.
