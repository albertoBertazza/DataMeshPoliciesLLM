import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class TrinoTestGenerator:
    """
    Generate executable Trino authorization tests from resolved
    authorization decisions.

    Inputs:
        - resolved authorization decisions
        - users
        - Data Mesh structure
        - action -> SQL mapping

    The Data Mesh is authoritative for resources that physically exist.

    Each generated test contains enough provenance to map the SQL
    test back to the resolver result:

        securityGroup
        resourcePath
        action
        resource
        query
        username
        password
        allowed
    """

    def __init__(
        self,
        users_file: str | Path,
        data_mesh_file: str | Path,
        action_sql_mapping_file: str | Path,
    ):
        self.users_file = Path(users_file)
        self.data_mesh_file = Path(data_mesh_file)
        self.action_sql_mapping_file = Path(action_sql_mapping_file)

        self.users = self._load_json(self.users_file)
        self.data_mesh = self._load_json(self.data_mesh_file)
        self.action_sql_mapping = self._load_json(
            self.action_sql_mapping_file
        )

        self.resources = self._flatten_data_mesh()

    # =========================================================
    # JSON
    # =========================================================

    @staticmethod
    def _load_json(path: Path) -> Any:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

    # =========================================================
    # USER
    # =========================================================

    @staticmethod
    def _users_by_group(
        users: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:

        result: Dict[str, List[Dict[str, Any]]] = {}

        for user in users:
            for group in user.get("groups", []):
                result.setdefault(group, []).append(user)

        return result

    # =========================================================
    # DATA MESH
    # =========================================================

    def _flatten_data_mesh(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Convert the hierarchical Data Mesh into convenient lists.

        The Data Mesh is authoritative for resources that physically
        exist.
        """

        result = {
            "catalogs": [],
            "schemas": [],
            "tables": [],
            "columns": [],
        }

        for catalog in self.data_mesh.get("catalogs", []):

            catalog_name = catalog.get("name")

            if not catalog_name:
                continue

            result["catalogs"].append(
                {
                    "catalog": catalog_name
                }
            )

            for schema in catalog.get("schemas", []):

                schema_name = schema.get("name")

                if not schema_name:
                    continue

                result["schemas"].append(
                    {
                        "catalog": catalog_name,
                        "schema": schema_name,
                    }
                )

                for table in schema.get("tables", []):

                    table_name = table.get("name")

                    if not table_name:
                        continue

                    result["tables"].append(
                        {
                            "catalog": catalog_name,
                            "schema": schema_name,
                            "table": table_name,
                        }
                    )

                    for column in table.get("columns", []):

                        column_name = column.get("name")

                        if not column_name:
                            continue

                        result["columns"].append(
                            {
                                "catalog": catalog_name,
                                "schema": schema_name,
                                "table": table_name,
                                "column": column_name,
                                "column_type": column.get(
                                    "type",
                                    "varchar"
                                ),
                            }
                        )

        return result

    # =========================================================
    # RESOURCE MATCHING
    # =========================================================

    @staticmethod
    def _same_resource(
        resource: Dict[str, Any],
        candidate: Dict[str, Any],
        level: str,
    ) -> bool:

        if level == "catalog":
            return (
                resource.get("catalog")
                == candidate.get("catalog")
            )

        if level == "schema":
            return (
                resource.get("catalog")
                == candidate.get("catalog")
                and resource.get("schema")
                == candidate.get("schema")
            )

        if level == "table":
            return (
                resource.get("catalog")
                == candidate.get("catalog")
                and resource.get("schema")
                == candidate.get("schema")
                and resource.get("table")
                == candidate.get("table")
            )

        if level == "column":
            return (
                resource.get("catalog")
                == candidate.get("catalog")
                and resource.get("schema")
                == candidate.get("schema")
                and resource.get("table")
                == candidate.get("table")
                and resource.get("column")
                == candidate.get("column")
            )

        return False

    # =========================================================
    # DATA MESH LOOKUP
    # =========================================================

    def _find_catalog(
        self,
        resource: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:

        for candidate in self.resources["catalogs"]:
            if self._same_resource(resource, candidate, "catalog"):
                return candidate

        return None

    def _find_schema(
        self,
        resource: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:

        for candidate in self.resources["schemas"]:
            if self._same_resource(resource, candidate, "schema"):
                return candidate

        return None

    def _find_table(
        self,
        resource: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:

        for candidate in self.resources["tables"]:
            if self._same_resource(resource, candidate, "table"):
                return candidate

        return None

    def _find_column(
        self,
        resource: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:

        for candidate in self.resources["columns"]:
            if self._same_resource(resource, candidate, "column"):
                return candidate

        return None

    # =========================================================
    # RESOURCE CONTEXT
    # =========================================================

    def _build_resource_context(
        self,
        resource: Dict[str, Any],
        resource_level: str,
    ) -> Optional[Dict[str, Any]]:

        catalog = resource.get("catalog")
        schema = resource.get("schema")
        table = resource.get("table")
        column = resource.get("column")

        if not catalog:
            return None

        # -----------------------------------------------------
        # catalog
        # -----------------------------------------------------

        if self._find_catalog(
            {"catalog": catalog}
        ) is None:
            return None

        context: Dict[str, Any] = {
            "catalog": catalog
        }

        # -----------------------------------------------------
        # schema
        # -----------------------------------------------------

        if resource_level in {
            "schema",
            "table",
            "column",
        }:

            if not schema:
                return None

            if self._find_schema(
                {
                    "catalog": catalog,
                    "schema": schema,
                }
            ) is None:
                return None

            context["schema"] = schema

        # -----------------------------------------------------
        # table
        # -----------------------------------------------------

        if resource_level in {
            "table",
            "column",
        }:

            if not table:
                return None

            if self._find_table(
                {
                    "catalog": catalog,
                    "schema": schema,
                    "table": table,
                }
            ) is None:
                return None

            context["table"] = table

        # -----------------------------------------------------
        # column
        # -----------------------------------------------------

        if resource_level == "column":

            if not column:
                return None

            column_resource = self._find_column(
                {
                    "catalog": catalog,
                    "schema": schema,
                    "table": table,
                    "column": column,
                }
            )

            if column_resource is None:
                return None

            context["column"] = column
            context["column_type"] = column_resource[
                "column_type"
            ]

        return context

    # =========================================================
    # ACTION VALUES
    # =========================================================

    @staticmethod
    def _column_value(column_type: str) -> str:

        normalized = column_type.lower()

        if any(
            x in normalized
            for x in (
                "int",
                "decimal",
                "double",
                "real",
                "float",
            )
        ):
            return "0"

        if "boolean" in normalized:
            return "FALSE"

        if "timestamp" in normalized:
            return "TIMESTAMP '2000-01-01 00:00:00'"

        if "date" in normalized:
            return "DATE '2000-01-01'"

        return "'test'"

    def _add_action_values(
        self,
        action: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        result = dict(context)

        if "column" in result:

            column_type = result.get(
                "column_type",
                "varchar"
            )

            result["value"] = self._column_value(
                column_type
            )

            result["new_column"] = (
                f"{result['column']}_renamed"
            )

        table = result.get("table")
        schema = result.get("schema")

        if table:

            result["test_table"] = (
                f"{table}_test"
            )

            result["test_view"] = (
                f"{table}_test_view"
            )

            result["test_materialized_view"] = (
                f"{table}_test_mv"
            )

            result["renamed_table"] = (
                f"{table}_renamed"
            )

            result["renamed_view"] = (
                f"{table}_renamed_view"
            )

            result["renamed_materialized_view"] = (
                f"{table}_renamed_mv"
            )

        if schema:

            result["test_schema"] = (
                f"{schema}_test"
            )

            result["renamed_schema"] = (
                f"{schema}_renamed"
            )

        return result

    # =========================================================
    # RESOURCE LEVEL
    # =========================================================

    def _get_context(
        self,
        action: str,
        resource: Dict[str, Any],
        mapping: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        resource_level = mapping.get(
            "resource_level"
        )

        if not resource_level:
            return None

        # -----------------------------------------------------
        # Existing resource
        # -----------------------------------------------------

        context = self._build_resource_context(
            resource,
            resource_level,
        )

        if context is not None:
            return self._add_action_values(
                action,
                context,
            )

        # -----------------------------------------------------
        # CREATE TABLE / VIEW / MV
        # -----------------------------------------------------

        if action in {
            "CreateTableAction",
            "CreateViewAction",
            "CreateMaterializedViewAction",
        }:

            parent_context = self._build_resource_context(
                resource,
                "schema",
            )

            if parent_context is None:
                return None

            return self._add_action_values(
                action,
                parent_context,
            )

        # -----------------------------------------------------
        # CREATE SCHEMA
        # -----------------------------------------------------

        if action == "CreateSchemaAction":

            parent_context = self._build_resource_context(
                resource,
                "catalog",
            )

            if parent_context is None:
                return None

            return self._add_action_values(
                action,
                parent_context,
            )

        return None

    # =========================================================
    # ACTION -> SQL
    # =========================================================

    def _action_to_query(
        self,
        action: str,
        resource: Dict[str, Any],
    ) -> Optional[str]:

        mapping = self.action_sql_mapping.get(action)

        if mapping is None:
            return None

        template = mapping.get("sql_template")

        if not template:
            return None

        context = self._get_context(
            action,
            resource,
            mapping,
        )

        if context is None:
            return None

        try:
            return template.format(**context)

        except (KeyError, ValueError, IndexError):
            return None

    # =========================================================
    # TEST GENERATION
    # =========================================================

    def generate(
        self,
        resolved: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Generate SQL tests directly from resolver output.

        The resolver is the source of the expected authorization
        decision.

        The generated test keeps the resolver provenance so the
        execution result can later be matched to:

            securityGroup + resourcePath + action
        """

        users_by_group = self._users_by_group(
            self.users
        )

        tests: List[Dict[str, Any]] = []

        for authorization in resolved:

            security_group = authorization.get(
                "securityGroup"
            )

            resource_path = authorization.get(
                "resourcePath"
            )

            resource = authorization.get(
                "resource",
                {}
            )

            actions = authorization.get(
                "actions",
                {}
            )

            users = users_by_group.get(
                security_group,
                []
            )

            for action_name, action_result in actions.items():

                if not isinstance(
                    action_result,
                    dict,
                ):
                    continue

                query = self._action_to_query(
                    action_name,
                    resource,
                )

                if query is None:
                    continue

                expected_allowed = bool(
                    action_result.get(
                        "allowed",
                        False,
                    )
                )

                for user in users:

                    username = user.get(
                        "username"
                    )

                    password = user.get(
                        "password"
                    )

                    if username is None:
                        continue

                    tests.append(
                        {
                            # Resolver provenance.
                            "securityGroup": security_group,
                            "resourcePath": resource_path,
                            "resource": resource,
                            "action": action_name,

                            # Executable test.
                            "query": query,
                            "username": username,
                            "password": password,

                            # Expected result from resolver.
                            "allowed": expected_allowed,
                        }
                    )

        print("=" * 60)
        print("TEST GENERATION")
        print("=" * 60)
        print(json.dumps(tests, indent=2, ensure_ascii=False))


        return tests

    # =========================================================
    # SAVE
    # =========================================================

    def save(
        self,
        resolved: List[Dict[str, Any]],
        output_file: str | Path,
    ) -> List[Dict[str, Any]]:

        tests = self.generate(resolved)

        output_file = Path(output_file)

        output_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with output_file.open(
            "w",
            encoding="utf-8",
        ) as f:

            json.dump(
                tests,
                f,
                indent=2,
                ensure_ascii=False,
            )

        return tests
