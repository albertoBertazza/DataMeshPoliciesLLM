from typing import Optional, Dict, Any


def build_opa_input(
    resource: Dict[str, Optional[str]],
    operation: str,
    security_group: str,
) -> Dict[str, Any]:
    """
    Build the input object expected by package trino.authz.

    Parameters
    ----------
    resource:
        Logical resource:
        {
            "catalog": str | None,
            "schema": str | None,
            "table": str | None,
            "column": str | None
        }

    operation:
        The Trino operation that will be assigned to
        input.action.operation.

    security_group:
        Security group of the user.

    Returns
    -------
    dict
        OPA input object.
    """

    catalog = resource.get("catalog")
    schema = resource.get("schema")
    table = resource.get("table")
    column = resource.get("column")

    # ------------------------------------------------------------
    # Build Trino resource object
    # ------------------------------------------------------------

    if column:
        if not catalog or not schema or not table:
            raise ValueError(
                "A column resource requires catalog, schema and table."
            )

        trino_resource = {
            "column": {
                "catalogName": catalog,
                "schemaName": schema,
                "tableName": table,
                "columnName": column,
            }
        }

    elif table:
        if not catalog or not schema:
            raise ValueError(
                "A table resource requires catalog and schema."
            )

        trino_resource = {
            "table": {
                "catalogName": catalog,
                "schemaName": schema,
                "tableName": table,
            }
        }

    elif schema:
        if not catalog:
            raise ValueError(
                "A schema resource requires catalog."
            )

        trino_resource = {
            "schema": {
                "catalogName": catalog,
                "schemaName": schema,
            }
        }

    elif catalog:
        trino_resource = {
            "catalog": {
                "name": catalog,
            }
        }

    else:
        trino_resource = {}

    # ------------------------------------------------------------
    # Build OPA input
    # ------------------------------------------------------------

    return {
        "context": {
            "identity": {
                "user": security_group,
                "groups": [security_group],
            }
        },
        "action": {
            "operation": operation,
            "resource": trino_resource,
        },
    }

'''
build_opa_input(
    resource={
        "catalog": "iceberg",
        "schema": "sales",
        "table": None,
        "column": None,
    },
    operation="ShowSchemas",
    security_group="sales_manager",
)
'''