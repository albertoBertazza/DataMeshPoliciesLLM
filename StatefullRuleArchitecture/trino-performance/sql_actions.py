# sql_actions.py


SQL_ACTIONS = {

    # ------------------------------------------------------------------
    # READ
    # ------------------------------------------------------------------

    "SelectFromTableAction": {
        "sql": (
            "SELECT * "
            "FROM {catalog}.{schema}.{table} "
            "LIMIT 5"
        ),
        "requires_table": True,
    },

    "SelectFromColumnsAction": {
        "sql": (
            "SELECT * "
            "FROM {catalog}.{schema}.{table} "
            "LIMIT 5"
        ),
        "requires_table": True,
    },

    # ------------------------------------------------------------------
    # METADATA
    # ------------------------------------------------------------------

    "ShowSchemasAction": {
        "sql": (
            "SHOW SCHEMAS "
            "FROM {catalog}"
        ),
        "requires_catalog": True,
    },

    "ShowTablesAction": {
        "sql": (
            "SHOW TABLES "
            "FROM {catalog}.{schema}"
        ),
        "requires_schema": True,
    },

    # ------------------------------------------------------------------
    # WRITE
    #
    # These are intentionally not executable by the performance runner
    # unless you explicitly enable them.
    # ------------------------------------------------------------------

    "InsertIntoTableAction": {
        "sql": (
            "INSERT INTO {catalog}.{schema}.{table} "
            "SELECT * "
            "FROM {catalog}.{schema}.{table} "
            "WHERE 1 = 0"
        ),
        "requires_table": True,
        "read_only": False,
    },

    "DeleteFromTableAction": {
        "sql": (
            "DELETE FROM {catalog}.{schema}.{table} "
            "WHERE 1 = 0"
        ),
        "requires_table": True,
        "read_only": False,
    },

    "UpdateTableAction": {
        "sql": (
            "UPDATE {catalog}.{schema}.{table} "
            "SET {first_column} = {first_column} "
            "WHERE 1 = 0"
        ),
        "requires_table": True,
        "read_only": False,
    },
}


# ------------------------------------------------------------------
# Normalization
# ------------------------------------------------------------------

def normalize_action_name(action):

    action = str(action).strip()

    if action.endswith("Action"):
        action = action[:-6]

    return action.lower()


def find_sql_action(action):

    normalized = normalize_action_name(action)

    for name, definition in SQL_ACTIONS.items():

        if normalize_action_name(name) == normalized:
            return name, definition

    return None, None


def build_sql(
    action,
    catalog=None,
    schema=None,
    table=None,
    first_column=None
):

    canonical_name, definition = find_sql_action(
        action
    )

    if definition is None:
        return None

    values = {
        "catalog": catalog,
        "schema": schema,
        "table": table,
        "first_column": first_column or "1",
    }

    try:
        return definition["sql"].format(
            **values
        )

    except KeyError:
        return None