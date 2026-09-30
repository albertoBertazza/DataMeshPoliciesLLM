import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

class TrinoTestGenerator:
    """
    Generate executable Trino authorization tests from resolved
    authorization decisions.

    Data Mesh object types
    ----------------------

    Every object inside schema["tables"] has:

        {
            "name": "...",
            "type": "table" | "view" | "materialized view",
            "columns": [...]
        }

    The Data Mesh is authoritative for physically existing resources.

    IMPORTANT:
    The resolver resource is always preserved exactly.

    The action SQL mapping's `resource_level` is used only to
    determine the SQL context required by the action.
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
        value = re.sub(r"[^A-Za-z0-9_]", "_", value)
        if not value:
            value = "user"
        return value

    @staticmethod
    def _create_test_run_id( username: Optional[str] = None ) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        if username:
            safe_username = TrinoTestGenerator._safe_identifier(username)
            return f"{safe_username}_{timestamp}"
        return timestamp

    # =========================================================
    # DATA MESH
    # =========================================================
    def _flatten_data_mesh( self ) -> Dict[str, List[Dict[str, Any]]]:
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

                    # -------------------------------------------------
                    # IMPORTANT:
                    #
                    # Data Mesh now stores:
                    #
                    #   type = table
                    #   type = view
                    #   type = materialized view
                    #
                    # Preserve that information.
                    # -------------------------------------------------
                    object_type = table.get("type", "table")
                    result["tables"].append( { "catalog": catalog_name, "schema": schema_name, "table": table_name, "type": object_type} )
                    for column in table.get("columns", []):
                        column_name = column.get("name")
                        if not column_name:
                            continue
                        result["columns"].append( { "catalog": catalog_name, "schema": schema_name, "table": table_name, "column": column_name, "column_type": column.get( "type", "varchar" ), "object_type": object_type} )
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

    # =========================================================
    # FIND OBJECT
    # =========================================================

    def _find_object( self, resource: Dict[str, Any], object_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Find an object in the Data Mesh.

        object_type can be:

            table
            view
            materialized view

        If object_type is None, any object type is accepted.
        """
        for candidate in self.resources["tables"]:
            if not self._same_resource( resource, candidate, "table"):
                continue
            if object_type is not None:
                if candidate.get("type") != object_type:
                    continue
            return candidate
        return None

    # =========================================================
    # FIND TABLE
    # =========================================================

    def _find_table( self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Find a PHYSICAL TABLE.

        Views and materialized views are deliberately excluded.
        """
        return self._find_object( resource, "table")

    # =========================================================
    # FIND VIEW
    # =========================================================
    def _find_view( self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return self._find_object( resource, "view")

    # =========================================================
    # FIND MATERIALIZED VIEW
    # =========================================================
    def _find_materialized_view( self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return self._find_object( resource, "materialized view")

    # =========================================================
    # FIND COLUMN
    # =========================================================

    def _find_column( self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for candidate in self.resources["columns"]:
            if not self._same_resource( resource, candidate, "column"):
                continue
            return candidate
        return None

    # =========================================================
    # RESOURCE CONTEXT
    # =========================================================

    def _build_resource_context( self, resource: Dict[str, Any], resource_level: str) -> Optional[Dict[str, Any]]:
        catalog = resource.get("catalog")
        schema = resource.get("schema")
        table = resource.get("table")
        column = resource.get("column")
        if not catalog:
            return None

        # -----------------------------------------------------
        # CATALOG
        # -----------------------------------------------------
        if self._find_catalog( {"catalog": catalog} ) is None:
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
            # IMPORTANT:
            # This requires type == "table".
            #
            # A view or materialized view with the same name
            # must not satisfy a table operation.
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
            context["column_type"] = column_resource[ "column_type" ]
        return context

    # =========================================================
    # ACTION VALUES
    # =========================================================

    @staticmethod
    def _column_value(column_type: str) -> str:
        normalized = column_type.lower()
        if any( x in normalized for x in ( "int", "decimal", "double", "real", "float") ):
            return "0"
        if "boolean" in normalized:
            return "FALSE"
        if "timestamp" in normalized:
            return "TIMESTAMP '2000-01-01 00:00:00'"
        if "date" in normalized:
            return "DATE '2000-01-01'"
        return "'test'"

    def _add_action_values( self, action: str, context: Dict[str, Any], username: Optional[str] = None, test_run_id: Optional[str] = None) -> Dict[str, Any]:
        result = dict(context)
        if test_run_id is None:
            test_run_id = self._create_test_run_id( username )

        # -----------------------------------------------------
        # COLUMN
        # -----------------------------------------------------
        if "column" in result:
            column_type = result.get( "column_type", "varchar")
            result["value"] = self._column_value( column_type )
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

    # =========================================================
    # FIND TABLE IN SCHEMA
    # =========================================================

    def _find_table_in_schema( self, catalog: str, schema: str) -> Optional[Dict[str, Any]]:
        """
        Return one existing PHYSICAL TABLE from the schema.

        IMPORTANT:

        Views and materialized views are ignored.
        """
        for candidate in self.resources["tables"]:
            if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema and candidate.get("type") == "table" ):
                return candidate
        return None

    # =========================================================
    # FIND TABLE IN CATALOG
    # =========================================================

    def _find_table_in_catalog( self, catalog: str) -> Optional[Dict[str, Any]]:
        """
        Return one existing PHYSICAL TABLE from the catalog.

        Views and materialized views are ignored.
        """
        for candidate in self.resources["tables"]:
            if ( candidate.get("catalog") == catalog and candidate.get("type") == "table" ):
                return candidate
        return None

    # =========================================================
    # SQL CONTEXT
    # =========================================================

    def _get_context( self, action: str, resource: Dict[str, Any], mapping: Dict[str, Any], username: Optional[str] = None, test_run_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        resource_level = mapping.get("resource_level")
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
            if table:
                table_resource = self._find_table( { "catalog": catalog, "schema": schema, "table": table} )
            else:
                table_resource = self._find_table_in_schema( catalog, schema)
            if table_resource is None:
                print( f"[TEST SKIP] No physical table found " f"for AddColumnAction inside " f"'{catalog}.{schema}'" )
                return None
            context = { "catalog": table_resource["catalog"], "schema": table_resource["schema"], "table": table_resource["table"]}
            return self._add_action_values( action, context, username, test_run_id)

        # =====================================================
        # DELETE FROM TABLE
        # =====================================================
        if action == "DeleteFromTableAction":
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            table = resource.get("table")
            if not catalog or not schema:
                return None
            if table:
                table_resource = self._find_table( { "catalog": catalog, "schema": schema, "table": table} )
            else:
                table_resource = self._find_table_in_schema( catalog, schema)
            if table_resource is None:
                print( f"[TEST SKIP] No physical table found " f"for DeleteFromTableAction inside " f"'{catalog}.{schema}'" )
                return None
            context = { "catalog": table_resource["catalog"], "schema": table_resource["schema"], "table": table_resource["table"]}
            return self._add_action_values( action, context, username, test_run_id)

        # =====================================================
        # CREATE SCHEMA
        # =====================================================
        if action == "CreateSchemaAction":
            parent_context = self._build_resource_context( resource, "catalog")
            if parent_context is None:
                return None
            if test_run_id is None:
                test_run_id = self._create_test_run_id( username )
            base_schema = ( resource.get("schema") or "test_schema" )
            parent_context["test_schema"] = ( f"{base_schema}_test_{test_run_id}" )
            return parent_context

        # =====================================================
        # CREATE TABLE
        # =====================================================
        if action == "CreateTableAction":
            parent_context = self._build_resource_context( resource, "schema")
            if parent_context is None:
                return None
            if test_run_id is None:
                test_run_id = self._create_test_run_id( username )
            parent_context["test_table"] = ( f"test_table_{test_run_id}" )
            return parent_context

        # =====================================================
        # CREATE VIEW / MATERIALIZED VIEW
        # =====================================================
        if action in { "CreateViewAction", "CreateMaterializedViewAction"}:
            parent_context = self._build_resource_context( resource, "schema")
            if parent_context is None:
                return None
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            table = resource.get("table")
            if not table:
                return None

            # -------------------------------------------------
            # IMPORTANT:
            #
            # The source relation for CREATE VIEW / CREATE
            # MATERIALIZED VIEW must be a real physical TABLE.
            #
            # A VIEW or MATERIALIZED VIEW is not accepted here.
            # -------------------------------------------------
            table_resource = self._find_table( { "catalog": catalog, "schema": schema, "table": table} )
            if table_resource is None:
                print( f"[TEST SKIP] Source is not a physical table " f"for {action}: " f"'{catalog}.{schema}.{table}'" )
                return None
            parent_context["table"] = ( table_resource["table"] )
            return self._add_action_values( action, parent_context, username, test_run_id)

        # =====================================================
        # SHOW TABLES
        # =====================================================
        if action == "ShowTablesAction":
            context = self._build_resource_context( resource, "schema")
            if context is None:
                return None
            return context

        # =====================================================
        # RENAME VIEW
        # =====================================================
        if action == "RenameViewAction":
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            if not catalog or not schema:
                return None
            # The resolver target is schema-level, so there is
            # no view name in the resource. Find an existing
            # physical VIEW inside the schema.
            view_resource = None
            for candidate in self.resources["tables"]:
                if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema and candidate.get("type") == "view" ):
                    view_resource = candidate
                    break
            if view_resource is None:
                print( f"[TEST SKIP] No physical view found " f"for RenameViewAction inside " f"'{catalog}.{schema}'" )
                return None
            if test_run_id is None:
                test_run_id = self._create_test_run_id(username)
            view_name = view_resource["table"]
            context = {
                "catalog": catalog,
                "schema": schema,
                # Template already adds catalog.schema here.
                "test_view": view_name,
                # Trino requires the destination relation to be
                # schema-qualified when no session schema is set.
                "renamed_view": ( f"{catalog}.{schema}." f"{view_name}_renamed_{test_run_id}" ),
            }
            print( f"[TEST DEBUG] RenameViewAction: " f"using physical view " f"'{catalog}.{schema}.{view_name}'" )
            return context

        # =====================================================
        # RENAME MATERIALIZED VIEW
        # =====================================================
        if action == "RenameMaterializedViewAction":
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            if not catalog or not schema:
                return None
            # The resolver target is schema-level, so the
            # materialized view name is not present in the resource.
            # Find an existing physical materialized view in the schema.
            materialized_view_resource = None
            for candidate in self.resources["tables"]:
                if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema and candidate.get("type") == "materialized view" ):
                    materialized_view_resource = candidate
                    break
            if materialized_view_resource is None:
                print( f"[TEST SKIP] No physical materialized view found " f"for RenameMaterializedViewAction inside " f"'{catalog}.{schema}'" )
                return None
            if test_run_id is None:
                test_run_id = self._create_test_run_id(username)
            materialized_view_name = materialized_view_resource["table"]
            context = {
                "catalog": catalog,
                "schema": schema,
                # Template already adds catalog.schema.
                "test_materialized_view": materialized_view_name,
                # Template also adds catalog.schema to the destination.
                "renamed_materialized_view": ( f"{materialized_view_name}_renamed_{test_run_id}" ),
            }
            print( f"[TEST DEBUG] RenameMaterializedViewAction: " f"using physical materialized view " f"'{catalog}.{schema}.{materialized_view_name}'" )
            return context

        # =====================================================
        # SHOW SCHEMAS
        # =====================================================
        if action == "ShowSchemasAction":
            context = self._build_resource_context( resource, "catalog")
            if context is None:
                return None
            return context

        # =====================================================
        # SET VIEW COMMENT
        # =====================================================
        if action == "SetViewCommentAction":
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            if not catalog or not schema:
                return None
            # The resolver target is schema-level, so the view name
            # is not present in the resource. Find an existing
            # physical VIEW inside the schema.
            view_resource = None
            for candidate in self.resources["tables"]:
                if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema and candidate.get("type") == "view" ):
                    view_resource = candidate
                    break
            if view_resource is None:
                print( f"[TEST SKIP] No physical view found " f"for SetViewCommentAction inside " f"'{catalog}.{schema}'" )
                return None
            if test_run_id is None:
                test_run_id = self._create_test_run_id(username)
            view_name = view_resource["table"]
            context = {
                "catalog": catalog,
                "schema": schema,
                # The template already adds catalog.schema.
                "test_view": view_name,
            }
            print( f"[TEST DEBUG] SetViewCommentAction: " f"using physical view " f"'{catalog}.{schema}.{view_name}'" )
            return context

        # =====================================================
        # REFRESH MATERIALIZED VIEW
        # =====================================================
        if action == "RefreshMaterializedViewAction":
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            if not catalog or not schema:
                return None
            # The resolver target is schema-level, so the
            # materialized view name is not present in the resource.
            # Find an existing physical materialized view in the schema.
            materialized_view_resource = None
            for candidate in self.resources["tables"]:
                if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema and candidate.get("type") == "materialized view" ):
                    materialized_view_resource = candidate
                    break
            if materialized_view_resource is None:
                print( f"[TEST SKIP] No physical materialized view found " f"for RefreshMaterializedViewAction inside " f"'{catalog}.{schema}'" )
                return None
            if test_run_id is None:
                test_run_id = self._create_test_run_id(username)
            materialized_view_name = materialized_view_resource["table"]
            context = {
                "catalog": catalog,
                "schema": schema,
                # The template already adds catalog.schema.
                "test_materialized_view": materialized_view_name,
            }
            print( f"[TEST DEBUG] RefreshMaterializedViewAction: " f"using physical materialized view " f"'{catalog}.{schema}.{materialized_view_name}'" )
            return context

        # =====================================================
        # DROP MATERIALIZED VIEW
        # =====================================================
        if action == "DropMaterializedViewAction":
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            if not catalog or not schema:
                return None
            # The resolver target is schema-level, so the
            # materialized view name is not present in the resource.
            # Find an existing physical materialized view in the schema.
            materialized_view_resource = None
            for candidate in self.resources["tables"]:
                if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema and candidate.get("type") == "materialized view" ):
                    materialized_view_resource = candidate
                    break
            if materialized_view_resource is None:
                print( f"[TEST SKIP] No physical materialized view found " f"for DropMaterializedViewAction inside " f"'{catalog}.{schema}'" )
                return None
            if test_run_id is None:
                test_run_id = self._create_test_run_id(username)
            materialized_view_name = materialized_view_resource["table"]
            context = {
                "catalog": catalog,
                "schema": schema,
                # The template already adds catalog.schema.
                "test_materialized_view": materialized_view_name,
            }
            print( f"[TEST DEBUG] DropMaterializedViewAction: " f"using physical materialized view " f"'{catalog}.{schema}.{materialized_view_name}'" )
            return context

        # =====================================================
        # DROP VIEW
        # =====================================================
        if action == "DropViewAction":
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            if not catalog or not schema:
                return None
            # The resolver target is schema-level, so the view name
            # is not present in the resource. Find an existing
            # physical VIEW inside the schema.
            view_resource = None
            for candidate in self.resources["tables"]:
                if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema and candidate.get("type") == "view" ):
                    view_resource = candidate
                    break
            if view_resource is None:
                print( f"[TEST SKIP] No physical view found " f"for DropViewAction inside " f"'{catalog}.{schema}'" )
                return None
            if test_run_id is None:
                test_run_id = self._create_test_run_id(username)
            view_name = view_resource["table"]
            context = {
                "catalog": catalog,
                "schema": schema,
                # The template already adds catalog.schema.
                "test_view": view_name,
            }
            print( f"[TEST DEBUG] DropViewAction: " f"using physical view " f"'{catalog}.{schema}.{view_name}'" )
            return context

        # =====================================================
        # DROP SCHEMA
        # =====================================================
        if action == "DropSchemaAction":
            context = self._build_resource_context( resource, "schema")
            if context is None:
                return None
            return self._add_action_values( action, context, username, test_run_id)

        # =====================================================
        # DROP TABLE
        # =====================================================
        if action == "DropTableAction":
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            table = resource.get("table")
            if not catalog or not schema or not table:
                return None
            # IMPORTANT:
            # Must be a physical TABLE.
            table_resource = self._find_table( { "catalog": catalog, "schema": schema, "table": table} )
            if table_resource is None:
                print( f"[TEST SKIP] No physical table found " f"for DropTableAction: " f"'{catalog}.{schema}.{table}'" )
                return None
            context = { "catalog": table_resource["catalog"], "schema": table_resource["schema"], "table": table_resource["table"]}
            return self._add_action_values( action, context, username, test_run_id)
        # =====================================================
        # DROP COLUMN
        # =====================================================
        if action == "DropColumnAction":
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            table = resource.get("table")
            if not catalog or not schema or not table:
                return None
            # DROP COLUMN requires a physical TABLE.
            table_resource = self._find_table( { "catalog": catalog, "schema": schema, "table": table} )
            if table_resource is None:
                print( f"[TEST SKIP] No physical table found " f"for DropColumnAction: " f"'{catalog}.{schema}.{table}'" )
                return None
            column_resource = None
            for candidate in self.resources["columns"]:
                if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema and candidate.get("table") == table and candidate.get("object_type") == "table" ):
                    column_resource = candidate
                    break
            if column_resource is None:
                print( f"[TEST SKIP] No physical column found " f"for DropColumnAction: " f"'{catalog}.{schema}.{table}'" )
                return None
            context = { "catalog": catalog, "schema": schema, "table": table, "column": column_resource["column"]}
            return self._add_action_values( action, context, username, test_run_id)

        # =====================================================
        # SHOW CREATE SCHEMA
        # =====================================================
        if action == "ShowCreateSchemaAction":
            catalog = resource.get("catalog")
            if not catalog:
                return None
            schema = resource.get("schema")
            if schema:
                schema_resource = self._find_schema( { "catalog": catalog, "schema": schema} )
                if schema_resource is None:
                    return None
                return { "catalog": catalog, "schema": schema}
            for candidate in self.resources["schemas"]:
                if candidate.get("catalog") == catalog:
                    return { "catalog": catalog, "schema": candidate["schema"]}
            print( f"[TEST SKIP] No existing schema found " f"for catalog '{catalog}'" )
            return None

        # =====================================================
        # TABLE ACTIONS FROM HIGHER-LEVEL RESOURCES
        # =====================================================
        if ( resource_level == "table" and not resource.get("table") ):
            catalog = resource.get("catalog")
            schema = resource.get("schema")
            if not catalog:
                return None

            # -------------------------------------------------
            # CATALOG-LEVEL AUTHORIZATION
            # -------------------------------------------------
            if not schema:
                table_resource = ( self._find_table_in_catalog( catalog ) )
                if table_resource is None:
                    print( f"[TEST SKIP] No existing physical " f"table found inside catalog " f"'{catalog}'" )
                    return None
                schema = table_resource["schema"]
                table = table_resource["table"]

            # -------------------------------------------------
            # SCHEMA-LEVEL AUTHORIZATION
            # -------------------------------------------------
            else:
                table_resource = ( self._find_table_in_schema( catalog, schema) )
                if table_resource is None:
                    print( f"[TEST SKIP] No existing physical " f"table found for schema " f"'{catalog}.{schema}'" )
                    return None
                table = table_resource["table"]

            # -------------------------------------------------
            # FIND COLUMN
            # -------------------------------------------------
            column_resource = None
            for candidate in self.resources["columns"]:
                if ( candidate.get("catalog") == catalog and candidate.get("schema") == schema and candidate.get("table") == table and candidate.get("object_type") == "table" ):
                    column_resource = candidate
                    break

            # -------------------------------------------------
            # BUILD SQL CONTEXT
            # -------------------------------------------------
            context = { "catalog": catalog, "schema": schema, "table": table}
            if column_resource is not None:
                context["column"] = ( column_resource["column"] )
                context["column_type"] = ( column_resource.get( "column_type", "varchar") )
            return self._add_action_values( action, context, username, test_run_id)
        return None

    # =========================================================
    # ACTION -> SQL
    # =========================================================

    def _action_to_query( self, action: str, resource: Dict[str, Any], username: Optional[str] = None, test_run_id: Optional[str] = None) -> Optional[str]:
        mapping = self.action_sql_mapping.get(action)
        print( f"[SQL DEBUG] action={action}" )
        print( f"[SQL DEBUG] mapping=" f"{json.dumps(mapping, indent=2)}" )
        if mapping is None:
            return None
        template = mapping.get("sql_template")
        print( f"[SQL DEBUG] template={template}" )
        if not template:
            return None
        context = self._get_context( action, resource, mapping, username, test_run_id)
        print( f"[SQL DEBUG] context={context}" )
        if context is None:
            return None
        try:
            query = template.format(**context)
            print( f"[SQL DEBUG] query={query}" )
            return query
        except ( KeyError, ValueError, IndexError) as e:
            print( f"[SQL ERROR] action='{action}', " f"error={e}" )
            print( f"[SQL ERROR] template={template}" )
            print( f"[SQL ERROR] context={context}" )
            return None

    # =========================================================
    # RESOLVER TARGET DEDUPLICATION
    # =========================================================

    def _collapse_resolved_targets( self, resolved_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique: Dict[ tuple, Dict[str, Any] ] = {}
        for authorization in resolved_results:
            resource = authorization.get( "resource", {})
            if not isinstance(resource, dict):
                resource = {}
            resource_key = ( authorization.get( "securityGroup", ""), authorization.get( "resourcePath", ""), tuple( sorted( resource.items() ) ))
            unique[resource_key] = authorization
        return list(unique.values())

    # =========================================================
    # TEST GENERATION
    # =========================================================

    def generate( self, resolved: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        users_by_group = self._users_by_group( self.users )
        tests: List[Dict[str, Any]] = []
        resolved_targets = ( self._collapse_resolved_targets( resolved ) )
        print( f"[TEST DEBUG] Resolver entries: " f"{len(resolved)}" )
        print( f"[TEST DEBUG] Test targets after " f"deduplication: " f"{len(resolved_targets)}" )

        # =====================================================
        # AUTHORIZATION TARGETS
        # =====================================================

        for authorization in resolved_targets:
            security_group = authorization.get( "securityGroup" )
            resource_path = authorization.get( "resourcePath" )
            resource = authorization.get( "resource", {})
            if not isinstance(resource, dict):
                resource = {}
            actions = authorization.get( "actions", {})
            users = users_by_group.get( security_group, [])

            # =================================================
            # ACTIONS
            # =================================================

            for action_name, action_result in actions.items():
                mapping = ( self.action_sql_mapping.get( action_name, {}) )
                resource_level = mapping.get( "resource_level" )
                print( f"[TEST DEBUG] " f"group={security_group}, " f"users={len(users)}, " f"action={action_name}, " f"resource_level={resource_level}, " f"resource={resource}, " f"resourcePath={resource_path}" )
                if not isinstance( action_result, dict):
                    continue
                expected_allowed = bool( action_result.get( "allowed", False) )
                # =================================================
                # ONE USER PER SECURITY GROUP
                # =================================================
                users = users_by_group.get( security_group, [])
                if not users:
                    print( f"[TEST SKIP] No user found " f"for security group " f"'{security_group}'" )
                    continue
                user = users[0]
                username = user.get( "username" )
                password = user.get( "password" )
                if username is None:
                    print( f"[TEST SKIP] User for group " f"'{security_group}' " f"has no username" )
                    continue
                print( f"[TEST DEBUG] Using user=" f"'{username}' " f"for security group=" f"'{security_group}'" )

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
                        # Preserve resolver resource exactly.
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
