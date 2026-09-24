import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

class TrinoTestGenerator:
    """
    Generate executable Trino authorization tests from resolved
    authorization decisions.

    Resource semantics
    ------------------

    The AuthorizationResolver determines the authorization target
    from the resource explicitly expressed by the rewritten rule.

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

        resourceType:
            table

    The generator MUST preserve that resource.

    The action SQL mapping's `resource_level` is used only to
    determine the authorization/SQL context required by the action.

    It must NOT remove information from the resolver resource.

    Example:

        CreateMaterializedViewAction
            resource_level = "schema"

    The authorization target is schema-level, but the SQL still
    requires the existing source table:

        CREATE MATERIALIZED VIEW iceberg.hr.<view>
        AS SELECT * FROM iceberg.hr.people LIMIT 5;

    Therefore:

        resource = iceberg / hr / people

    is preserved.

    The Data Mesh remains authoritative for resources that physically
    exist.

    Generated temporary/test object names are made unique using:

        username + timestamp
    """

    def __init__( self, users_file: str | Path, data_mesh_file: str | Path, action_sql_mapping_file: str | Path):
        self.users_file = Path(users_file)
        self.data_mesh_file = Path(data_mesh_file)
        self.action_sql_mapping_file = Path(action_sql_mapping_file)

        self.users = self._load_json(self.users_file)
        self.data_mesh = self._load_json(self.data_mesh_file)
        self.action_sql_mapping = self._load_json( self.action_sql_mapping_file )

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
    def _users_by_group( users: List[Dict[str, Any]] ) -> Dict[str, List[Dict[str, Any]]]:
        result: Dict[str, List[Dict[str, Any]]] = {}
        for user in users:
            for group in user.get("groups", []):
                result.setdefault(group, []).append(user)
        return result

    # =========================================================
    # IDENTIFIERS
    # =========================================================

    @staticmethod
    def _safe_identifier(value: str) -> str:
        value = str(value)
        value = re.sub( r"[^A-Za-z0-9_]", "_", value)
        if not value:
            value = "user"
        return value

    @staticmethod
    def _create_test_run_id( username: Optional[str] = None ) -> str:
        timestamp = datetime.now().strftime( "%Y%m%d_%H%M%S_%f" )
        if username:
            safe_username = ( TrinoTestGenerator._safe_identifier(username) )
            return f"{safe_username}_{timestamp}"
        return timestamp

    # =========================================================
    # DATA MESH
    # =========================================================

    def _flatten_data_mesh( self) -> Dict[str, List[Dict[str, Any]]]:
        result = { "catalogs": [], "schemas": [], "tables": [], "columns": []}
        for catalog in self.data_mesh.get("catalogs", []):
            catalog_name = catalog.get("name")
            if not catalog_name:
                continue
            result["catalogs"].append( { "catalog": catalog_name } )
            for schema in catalog.get("schemas", []):
                schema_name = schema.get("name")
                if not schema_name:
                    continue
                result["schemas"].append( { "catalog": catalog_name, "schema": schema_name} )
                for table in schema.get("tables", []):
                    table_name = table.get("name")
                    if not table_name:
                        continue
                    result["tables"].append( { "catalog": catalog_name, "schema": schema_name, "table": table_name} )
                    for column in table.get("columns", []):
                        column_name = column.get("name")
                        if not column_name:
                            continue
                        result["columns"].append( { "catalog": catalog_name, "schema": schema_name, "table": table_name, "column": column_name, "column_type": column.get( "type", "varchar")} )

        return result

    # =========================================================
    # RESOURCE MATCHING
    # =========================================================

    @staticmethod
    def _same_resource( resource: Dict[str, Any], candidate: Dict[str, Any], level: str) -> bool:
        if level == "catalog":
            return ( resource.get("catalog") == candidate.get("catalog") )
        if level == "schema":
            return ( resource.get("catalog") == candidate.get("catalog") and resource.get("schema") == candidate.get("schema") )
        if level == "table":
            return ( resource.get("catalog") == candidate.get("catalog") and resource.get("schema") == candidate.get("schema") and resource.get("table") == candidate.get("table") )
        if level == "column":
            return ( resource.get("catalog") == candidate.get("catalog") and resource.get("schema") == candidate.get("schema") and resource.get("table") == candidate.get("table") and resource.get("column") == candidate.get("column") )
        return False

    # =========================================================
    # DATA MESH LOOKUP
    # =========================================================

    def _find_catalog( self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for candidate in self.resources["catalogs"]:
            if self._same_resource( resource, candidate, "catalog"):
                return candidate
        return None

    def _find_schema( self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for candidate in self.resources["schemas"]:
            if self._same_resource( resource, candidate, "schema"):
                return candidate
        return None

    def _find_table( self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for candidate in self.resources["tables"]:
            if self._same_resource( resource, candidate, "table"):
                return candidate
        return None

    def _find_column( self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for candidate in self.resources["columns"]:
            if self._same_resource( resource, candidate, "column"):
                return candidate

        return None

    # =========================================================
    # RESOURCE CONTEXT
    # =========================================================

    def _build_resource_context( self, resource: Dict[str, Any], resource_level: str) -> Optional[Dict[str, Any]]:
        """
        Build the context corresponding to the requested level.

        This function validates physical resources against the
        Data Mesh.

        It does NOT change the original resolver resource.

        Example:

            resource:
                iceberg / hr / people

            resource_level:
                schema

        returns:

            {
                "catalog": "iceberg",
                "schema": "hr"
            }

        The original resource may still contain:

            table = people

        and that information can be used separately by SQL actions
        that need a source table.
        """

        catalog = resource.get("catalog")
        schema = resource.get("schema")
        table = resource.get("table")
        column = resource.get("column")

        if not catalog:
            return None

        # -----------------------------------------------------
        # CATALOG
        # -----------------------------------------------------

        if self._find_catalog( { "catalog": catalog } ) is None:
            return None

        context: Dict[str, Any] = { "catalog": catalog }
        # -----------------------------------------------------
        # SCHEMA
        # -----------------------------------------------------
        if resource_level in { "schema", "table", "column"}:
            if not schema:
                return None
            if self._find_schema( { "catalog": catalog, "schema": schema} ) is None:
                return None
            context["schema"] = schema

        # -----------------------------------------------------
        # TABLE
        # -----------------------------------------------------
        if resource_level in { "table", "column"}:
            if not table:
                return None
            if self._find_table( { "catalog": catalog, "schema": schema, "table": table} ) is None:
                return None
            context["table"] = table

        # -----------------------------------------------------
        # COLUMN
        # -----------------------------------------------------
        if resource_level == "column":
            if not column:
                return None
            column_resource = self._find_column( { "catalog": catalog, "schema": schema, "table": table, "column": column} )
            if column_resource is None:
                return None
            context["column"] = column
            context["column_type"] = ( column_resource["column_type"] )
        return context

    # =========================================================
    # ACTION VALUES
    # =========================================================

    @staticmethod
    def _column_value( column_type: str) -> str:
        normalized = column_type.lower()
        if any( x in normalized for x in ( "int", "decimal", "double", "real", "float") ):
            return "0"
        if "boolean" in normalized:
            return "FALSE"
        if "timestamp" in normalized:
            return ( "TIMESTAMP " "'2000-01-01 00:00:00'" )
        if "date" in normalized:
            return "DATE '2000-01-01'"
        return "'test'"

    def _add_action_values( self, action: str, context: Dict[str, Any], username: Optional[str] = None, test_run_id: Optional[str] = None) -> Dict[str, Any]:
        result = dict(context)
        if test_run_id is None:
            test_run_id = ( self._create_test_run_id(username) )

        # -----------------------------------------------------
        # COLUMN
        # -----------------------------------------------------
        if "column" in result:
            column_type = result.get( "column_type", "varchar")
            result["value"] = ( self._column_value(column_type) )
            result["new_column"] = ( f"{result['column']}" f"_renamed_{test_run_id}" )

        # -----------------------------------------------------
        # ADD COLUMN
        # -----------------------------------------------------
        if ( action == "AddColumnAction" and "table" in result ):
            result["new_column"] = ( f"test_added_column_{test_run_id}" )

        # -----------------------------------------------------
        # TABLE
        # -----------------------------------------------------
        table = result.get("table")
        if table:
            result["test_table"] = ( f"{table}_test_{test_run_id}" )
            result["test_view"] = ( f"{table}_test_view_{test_run_id}" )
            result["test_materialized_view"] = ( f"{table}_test_mv_{test_run_id}" )
            result["renamed_table"] = ( f"{table}_renamed_{test_run_id}" )
            result["renamed_view"] = ( f"{table}_renamed_view_{test_run_id}" )
            result["renamed_materialized_view"] = ( f"{table}_renamed_mv_{test_run_id}" )

        # -----------------------------------------------------
        # SCHEMA
        # -----------------------------------------------------
        schema = result.get("schema")
        if schema:
            result["test_schema"] = ( f"{schema}_test_{test_run_id}" )
            result["renamed_schema"] = ( f"{schema}_renamed_{test_run_id}" )
        return result

    # =================================
    # Helper find table
    # ================================

    def _find_table_in_schema( self, catalog: str, schema: str) -> Optional[Dict[str, Any]]:
        """
        Return one existing table from the given schema.

        The Data Mesh is authoritative for physically existing
        resources.
        """
        for candidate in self.resources["tables"]:
            if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema ):
                return candidate
        return None

    # =========================================================
    # SQL CONTEXT
    # =========================================================

    def _get_context( self, action: str, resource: Dict[str, Any], mapping: Dict[str, Any], username: Optional[str] = None, test_run_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Build the SQL context for an action.

        IMPORTANT:

        `resource_level` describes the level at which the action
        operates for authorization/SQL purposes.

        It does NOT mean that fields below that level should be
        deleted from the resolver resource.

        Some SQL actions need additional physical-resource data.

        Example:

            CreateMaterializedViewAction

            resource_level = schema

        Authorization target:
            iceberg/hr

        But SQL needs:
            iceberg/hr/people

        because `people` is the source table.

        Therefore the resolver resource is preserved and the
        required source table is added to the SQL context.
        """

        resource_level = mapping.get( "resource_level" )

        if not resource_level:
            return None

        # =====================================================
        # ADD COLUMN
        # =====================================================

        if action == "AddColumnAction":
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            table = resource.get("table")

            if not catalog or not schema:
                return None

            # The target table must already exist.
            if table:
                table_resource = self._find_table({ "catalog": catalog, "schema": schema, "table": table})
            else:
                # Higher-level authorization target:
                # choose one physical table from the schema.
                table_resource = self._find_table_in_schema( catalog, schema)
            if table_resource is None:
                print( f"[TEST SKIP] No physical table found for AddColumnAction inside '{catalog}.{schema}'")
                return None

            context = { "catalog": table_resource["catalog"], "schema": table_resource["schema"], "table": table_resource["table"]}

            return self._add_action_values(action, context, username, test_run_id)

        # =====================================================
        # DELETE FROM TABLE
        # =====================================================

        if action == "DeleteFromTableAction":
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            table = resource.get("table")

            if not catalog or not schema:
                return None

            # Exact table target
            if table:
                table_resource = self._find_table({ "catalog": catalog, "schema": schema, "table": table})
            else:
                # Higher-level authorization target:
                # choose one physical table from the schema.
                table_resource = self._find_table_in_schema( catalog, schema)

            if table_resource is None:
                print( f"[TEST SKIP] No physical table found for " f"DeleteFromTableAction inside '{catalog}.{schema}'" )
                return None

            context = { "catalog": table_resource["catalog"], "schema": table_resource["schema"], "table": table_resource["table"]}

            return self._add_action_values( action, context, username, test_run_id)

        # =====================================================
        # CREATE SCHEMA
        # =====================================================

        if action == "CreateSchemaAction":
            """
            an example:
            CREATE SCHEMA operates at catalog level.

            The schema being created does not need to exist.
            """
            parent_context = ( self._build_resource_context( resource, "catalog") )
            if parent_context is None:
                return None
            if test_run_id is None:
                test_run_id = ( self._create_test_run_id(username) )
            base_schema = ( resource.get("schema") or "test_schema" )
            parent_context["test_schema"] = ( f"{base_schema}_test_{test_run_id}" )
            return parent_context

        # =====================================================
        # CREATE TABLE
        # =====================================================

        if action == "CreateTableAction":
            """
            CREATE TABLE operates at schema level.

            The schema must already exist, but the table being created
            does not need to exist.

            Therefore the authorization resource is:

                iceberg.hr

            while the SQL additionally requires a generated table name:

                iceberg.hr.<test_table>
            """
            parent_context = ( self._build_resource_context( resource, "schema") )
            if parent_context is None:
                return None
            if test_run_id is None:
                test_run_id = ( self._create_test_run_id(username) )
            # The table does not exist yet, so it cannot come from
            # the Data Mesh. Generate a unique name for the test.
            parent_context["test_table"] = ( f"test_table_{test_run_id}" )
            return parent_context

        # =====================================================
        # CREATE VIEW / MATERIALIZED VIEW
        # =====================================================

        if action in { "CreateViewAction", "CreateMaterializedViewAction"}:
            """
            CREATE VIEW and CREATE MATERIALIZED VIEW operate at
            schema level but their SELECT statement uses an
            existing source table.

            Therefore:

                authorization resource:
                    iceberg/hr/people

                SQL context:
                    catalog = iceberg
                    schema  = hr
                    table   = people
            """
            parent_context = ( self._build_resource_context( resource, "schema") )
            if parent_context is None:
                return None
            table = resource.get("table")
            if not table:
                return None
            if self._find_table( { "catalog": resource.get("catalog"), "schema": resource.get("schema"), "table": table} ) is None:
                return None
            parent_context["table"] = table
            return self._add_action_values( action, parent_context, username, test_run_id)

        # =====================================================
        # SHOW TABLES
        # =====================================================

        if action == "ShowTablesAction":
            """
            SHOW TABLES operates at schema level.

            Authorization target:
                iceberg.sales

            SQL:
                SHOW TABLES FROM iceberg.sales
            """

            context = self._build_resource_context(resource, "schema")

            if context is None:
                return None

            return context
        # =====================================================
        # SHOW SCHEMAS
        # =====================================================

        if action == "ShowSchemasAction":
            """
            SHOW SCHEMAS operates at catalog level.

            Authorization target:
                iceberg

            SQL:
                SHOW SCHEMAS FROM iceberg
            """

            context = self._build_resource_context(resource, "catalog")

            if context is None:
                return None

            return context

        # =====================================================
        # DROP SCHEMA
        # =====================================================

        if action == "DropSchemaAction":
            """
            an example:

            DROP SCHEMA operates at schema level.
            The schema must already exist in the Data Mesh.
            """

            context = self._build_resource_context(resource, "schema")

            if context is None:
                return None

            return self._add_action_values( action, context, username, test_run_id)

        # =====================================================
        # DROP TABLE
        # =====================================================

        if action == "DropTableAction":
            """
            an example
            DROP TABLE operates on an existing table.
            """

            catalog = resource.get("catalog")
            schema = resource.get("schema")
            table = resource.get("table")

            if not catalog or not schema or not table:
                return None

            table_resource = self._find_table({ "catalog": catalog, "schema": schema, "table": table})

            if table_resource is None:
                print( f"[TEST SKIP] No physical table found for " f"DropTableAction: '{catalog}.{schema}.{table}'" )
                return None

            context = { "catalog": table_resource["catalog"], "schema": table_resource["schema"], "table": table_resource["table"]}

            return self._add_action_values( action, context, username, test_run_id)

        # =====================================================
        # DROP COLUMN
        # =====================================================

        if action == "DropColumnAction":
            """
            an example
            DROP COLUMN operates on a physical column.

            The resolver authorization target may be table-level.
            Therefore an existing column is selected from the
            Data Mesh only for SQL generation.
            """

            catalog = resource.get("catalog")
            schema = resource.get("schema")
            table = resource.get("table")

            if not catalog or not schema or not table:
                return None

            table_resource = self._find_table({ "catalog": catalog, "schema": schema, "table": table})

            if table_resource is None:
                print( f"[TEST SKIP] No physical table found for " f"DropColumnAction: '{catalog}.{schema}.{table}'" )
                return None

            column_resource = None

            for candidate in self.resources["columns"]:
                if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema and candidate.get("table") == table ):
                    column_resource = candidate
                    break

            if column_resource is None:
                print( f"[TEST SKIP] No physical column found for " f"DropColumnAction: '{catalog}.{schema}.{table}'" )
                return None

            context = { "catalog": catalog, "schema": schema, "table": table, "column": column_resource["column"]}

            return self._add_action_values( action, context, username, test_run_id)

        # =====================================================
        # SHOW CREATE SCHEMA
        # =====================================================

        if action == "ShowCreateSchemaAction":
            """
            Authorization target may be catalog-level:

                iceberg

            but SHOW CREATE SCHEMA requires an existing schema:

                SHOW CREATE SCHEMA iceberg.sales;

            Therefore the schema is selected from the Data Mesh
            only for SQL generation.

            The original resolver resource remains:

                {
                    "catalog": "iceberg",
                    "schema": "",
                    "table": "",
                    "column": ""
                }
            """

            catalog = resource.get("catalog")
            if not catalog:
                return None
            # If the rule explicitly specified a schema, use it.
            schema = resource.get("schema")
            if schema:
                schema_resource = self._find_schema({"catalog": catalog,"schema": schema,})
                if schema_resource is None:
                    return None
                return { "catalog": catalog, "schema": schema}

            # Otherwise choose an existing schema from the Data Mesh.
            for candidate in self.resources["schemas"]:
                if candidate.get("catalog") == catalog:
                    return { "catalog": catalog, "schema": candidate["schema"]}
            print( f"[TEST SKIP] No existing schema found for catalog '{catalog}'" )

            return None

        # =====================================================
        # TABLE ACTIONS FROM HIGHER-LEVEL RESOURCES
        # =====================================================

        if resource_level == "table" and not resource.get("table"):
            """
            The authorization target may be higher than table level.

            Examples:

                catalog:
                    iceberg

                schema:
                    iceberg.hr

                table:
                    iceberg.hr.people

            The resolver resource MUST remain unchanged.

            For SQL generation only, select one existing physical table
            from the Data Mesh that is inside the authorization scope.

            Therefore:

                resolver resource:
                    iceberg

                SQL context:
                    iceberg.<some_schema>.<some_table>

            or:

                resolver resource:
                    iceberg.hr

                SQL context:
                    iceberg.hr.<some_table>
            """

            catalog = resource.get("catalog")
            schema = resource.get("schema")
            if not catalog:
                return None
            # -----------------------------------------------------
            # CATALOG-LEVEL AUTHORIZATION
            # -----------------------------------------------------
            #
            # Example:
            #
            #   resource = iceberg
            #
            # Find one physical table anywhere inside the catalog.
            #
            if not schema:
                table_resource = None
                for candidate in self.resources["tables"]:
                    if candidate.get("catalog") == catalog:
                        table_resource = candidate
                        break
                if table_resource is None:
                    print( f"[TEST SKIP] No existing table found " f"inside catalog '{catalog}'" )
                    return None
                schema = table_resource["schema"]
                table = table_resource["table"]

            # -----------------------------------------------------
            # SCHEMA-LEVEL AUTHORIZATION
            # -----------------------------------------------------
            #
            # Example:
            #
            #   resource = iceberg.hr
            #
            # Find one physical table inside that schema.
            #
            else:
                table_resource = self._find_table_in_schema( catalog, schema)
                if table_resource is None:
                    print( f"[TEST SKIP] No existing table found for " f"schema '{catalog}.{schema}'" )
                    return None
                table = table_resource["table"]

            # -----------------------------------------------------
            # FIND A COLUMN IF THE ACTION NEEDS ONE
            # -----------------------------------------------------
            #
            # Some table actions such as INSERT need a physical
            # column. Select one only for SQL generation.
            #
            column_resource = None
            for candidate in self.resources["columns"]:
                if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema and candidate.get("table") == table ):
                    column_resource = candidate
                    break
            # -----------------------------------------------------
            # BUILD SQL CONTEXT ONLY
            # -----------------------------------------------------
            context = { "catalog": catalog, "schema": schema, "table": table}
            if column_resource is not None:
                context["column"] = column_resource["column"]
                context["column_type"] = column_resource.get( "column_type", "varchar")
            return self._add_action_values( action, context, username, test_run_id)

    # =========================================================
    # ACTION -> SQL
    # =========================================================

    def _action_to_query( self, action: str, resource: Dict[str, Any], username: Optional[str] = None, test_run_id: Optional[str] = None ) -> Optional[str]:
        mapping = self.action_sql_mapping.get(action)
        print(f"[SQL DEBUG] action={action}")
        print(f"[SQL DEBUG] mapping={json.dumps(mapping, indent=2)}")
        if mapping is None:
            return None
        template = mapping.get("sql_template")
        print(f"[SQL DEBUG] template={template}")
        if not template:
            return None
        context = self._get_context( action, resource, mapping, username, test_run_id)
        print(f"[SQL DEBUG] context={context}")
        if context is None:
            return None
        try:
            query = template.format(**context)
            print(f"[SQL DEBUG] query={query}")
            return query

        except (KeyError, ValueError, IndexError) as e:
            print( f"[SQL ERROR] action='{action}', " f"error={e}" )
            print(f"[SQL ERROR] template={template}")
            print(f"[SQL ERROR] context={context}")
            return None

    # =========================================================
    # RESOLVER TARGET DEDUPLICATION
    # =========================================================

    def _collapse_resolved_targets( self, resolved_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Defensive deduplication of resolver results.

        IMPORTANT:

        This method does NOT normalize resources using the action
        SQL mapping.

        The AuthorizationResolver already returns one target for
        the resource explicitly expressed by the rule.

        Therefore:

            catalog rule
                -> one catalog target

            schema rule
                -> one schema target

            table rule
                -> one table target

            column rule
                -> one column target

        No descendant expansion is collapsed here.

        The SQL action mapping's resource_level is deliberately
        ignored for target deduplication.
        """
        unique: Dict[ tuple, Dict[str, Any] ] = {}
        for authorization in resolved_results:
            resource = authorization.get( "resource", {})
            if not isinstance( resource, dict):
                resource = {}
            resource_key = ( authorization.get( "securityGroup", ""), authorization.get( "resourcePath", ""), tuple( sorted( resource.items() ) ))
            unique[resource_key] = authorization
        return list( unique.values() )

    # =========================================================
    # TEST GENERATION
    # =========================================================

    def generate( self, resolved: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate SQL tests directly from resolver output.

        IMPORTANT:

        Tests are generated from the resource explicitly returned
        by the AuthorizationResolver.

        The action SQL mapping does NOT change the authorization
        target.

        Example:

            Rule:
                hr_manager can create materialized view
                on iceberg.hr.people

            Resolver:
                resourceType = table
                resource = iceberg/hr/people

            Result:
                one authorization target

            Then one executable test is generated per matching user.

        For CreateMaterializedViewAction, the SQL mapping says
        resource_level = schema, but the table `people` is retained
        because it is needed as the source table in the SQL.
        """
        users_by_group = ( self._users_by_group( self.users ) )
        tests: List[Dict[str, Any]] = []

        # -----------------------------------------------------
        # Defensive deduplication only.
        #
        # No resource-level normalization occurs here.
        # -----------------------------------------------------
        resolved_targets = ( self._collapse_resolved_targets( resolved ) )
        print( f"[TEST DEBUG] " f"Resolver entries: {len(resolved)}" )
        print( f"[TEST DEBUG] " f"Test targets after deduplication: " f"{len(resolved_targets)}" )

        # =====================================================
        # AUTHORIZATION TARGETS
        # =====================================================

        for authorization in resolved_targets:
            security_group = authorization.get( "securityGroup" )
            resource_path = authorization.get( "resourcePath" )
            resource = authorization.get( "resource", {} )
            if not isinstance( resource, dict):
                resource = {}
            actions = authorization.get( "actions", {} )
            users = users_by_group.get( security_group, [])

            # =================================================
            # ACTIONS
            # =================================================
            for action_name, action_result in actions.items():
                mapping = ( self.action_sql_mapping.get( action_name, {} ) )
                resource_level = mapping.get( "resource_level" )
                print( f"[TEST DEBUG] " f"group={security_group}, " f"users={len(users)}, " f"action={action_name}, " f"resource_level={resource_level}, " f"resource={resource}, " f"resourcePath={resource_path}" )
                if not isinstance( action_result, dict):
                    continue

                # -------------------------------------------------
                # Expected authorization result
                # -------------------------------------------------
                expected_allowed = bool( action_result.get( "allowed", False) )

                # =================================================
                # ONE USER PER SECURITY GROUP
                # =================================================

                users = users_by_group.get( security_group, [])

                if not users:
                    print( f"[TEST SKIP] No user found for " f"security group " f"'{security_group}'" )
                    continue

                # -------------------------------------------------
                # Keep only one representative user.
                #
                # Currently this is the first user appearing in
                # the users file that belongs to this group.
                # -------------------------------------------------
                user = users[0]
                username = user.get( "username" )
                password = user.get( "password" )
                if username is None:
                    print( f"[TEST SKIP] User for group " f"'{security_group}' " f"has no username" )
                    continue
                print( f"[TEST DEBUG] " f"Using user='{username}' " f"for security group='{security_group}'" )

                # -------------------------------------------------
                # Unique test identifier
                # -------------------------------------------------
                test_run_id = ( self._create_test_run_id( username ) )

                # -------------------------------------------------
                # SQL
                # -------------------------------------------------
                query = self._action_to_query( action_name, resource, username, test_run_id)

                if query is None:
                    print( f"[TEST SKIP] Cannot generate SQL " f"for action='{action_name}', " f"resource={resource}" )

                    continue

                # -------------------------------------------------
                # Test
                # -------------------------------------------------

                tests.append(
                    {
                        "securityGroup": security_group,
                        "resourcePath": resource_path,
                        # Preserve the resolver resource exactly.
                        "resource": resource,
                        "action": action_name,
                        "query": query,
                        "username": username,
                        "password": password,
                        "allowed": expected_allowed,
                    }
                )
        # =====================================================
        # OUTPUT
        # =====================================================

        print("=" * 60)
        print("TEST GENERATION")
        print("=" * 60)

        print( json.dumps( tests, indent=2, ensure_ascii=False) )

        return tests

    # =========================================================
    # SAVE
    # =========================================================

    def save( self, resolved: List[Dict[str, Any]], output_file: str | Path) -> List[Dict[str, Any]]:
        tests = self.generate( resolved )
        output_file = Path( output_file )
        output_file.parent.mkdir( parents=True, exist_ok=True)
        with output_file.open( "w", encoding="utf-8") as f:

            json.dump( tests, f, indent=2, ensure_ascii=False)

        return tests
