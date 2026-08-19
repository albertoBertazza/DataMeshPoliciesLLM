Yes — **that is a very good benchmark**, but there is one important distinction.

Your comparison should be:

### Architecture A — Trino → OPA

For one SQL request such as:

```sql
SELECT name, salary
FROM iceberg.hr.employees;
```

Trino may perform the logical authorization checks:

```text
SelectFromTableAction
 ├── AccessCatalog
 ├── ExecuteQuery
 ├── GetColumnMask
 ├── GetRowFilters
 └── SelectFromColumns
```

So you can measure the **end-to-end authorization cost** of the Trino interaction:

```text
User
  │
  │ SELECT
  ▼
Trino
  │
  ├── OPA: AccessCatalog
  ├── OPA: ExecuteQuery
  ├── OPA: GetColumnMask
  ├── OPA: GetRowFilters
  └── OPA: SelectFromColumns
  │
  ▼
Query execution
```

### Architecture B — Stateless/direct OPA benchmark

Then you can bypass Trino and directly make the equivalent five OPA authorization requests:

```text
Benchmark
   │
   ├── OPA: AccessCatalog
   ├── OPA: ExecuteQuery
   ├── OPA: GetColumnMask
   ├── OPA: GetRowFilters
   └── OPA: SelectFromColumns
```

This lets you separate:

1. **OPA policy evaluation cost**
2. **HTTP/network overhead**
3. **Trino authorization orchestration overhead**
4. **Actual query execution cost**

---

## But I would NOT call the second architecture "stateless"

This is the important terminology point.

OPA itself is fundamentally designed to answer **individual policy queries**. You can absolutely send five independent queries to OPA. OPA doesn't require you to create some stateful session containing the previous four decisions.

So your comparison is better described as:

**Trino-integrated authorization vs direct OPA authorization**

rather than:

**stateful vs stateless OPA**

For example:

```text
                 ┌──────────────────┐
                 │      Trino       │
                 └────────┬─────────┘
                          │
             5 authorization requests
                          │
                          ▼
                    ┌───────────┐
                    │    OPA    │
                    └───────────┘
```

versus:

```text
                 Benchmark
                     │
             5 authorization requests
                     │
                     ▼
                ┌───────────┐
                │    OPA    │
                └───────────┘
```

The second isn't necessarily "more stateless" than the first.

---

# The really interesting benchmark

Given what you're researching with your permission tree, I think there is actually a **more interesting third architecture** to benchmark.

### Current approach

Five separate OPA evaluations:

```text
SELECT
  │
  ├── AccessCatalog ──────> OPA
  ├── ExecuteQuery ───────> OPA
  ├── GetColumnMask ──────> OPA
  ├── GetRowFilters ──────> OPA
  └── SelectFromColumns ───> OPA
```

If each is an HTTP request, you potentially have:

```text
5 × (network + JSON + OPA evaluation)
```
