import json
from typing import Any, Dict, Optional

from Function.jsonHelper import load_json

# ============================================================================
# Resource hierarchy
#
# 0 = root
# 1 = catalog
# 2 = schema
# 3 = table / view / materialized view
# 4 = column
# ============================================================================

RESOURCE_DEPTH = { "root": 0, "catalog": 1, "schema": 2, "table": 3, "view": 3, "materialized_view": 3, "column": 4}

class PermissionCompiler:
    """
    Compile the merged permission tree into the canonical local OPA policy.

    Merged tree:

        resource_values
        ├── root
        │   └── permissions
        │       ├── hr_manager
        │       │   ├── allow
        │       │   ├── deny
        │       │   ├── row_filter
        │       │   └── column_masks
        │       └── finance_manager
        │           └── ...
        │
        └── catalogs
            └── ...
                └── permissions
                    └── <security_group>
                        └── ...

    Responsibilities:
        - build the authoritative Data Mesh resource tree;
        - validate resource existence;
        - validate security groups;
        - validate permission depth;
        - validate local allow/deny conflicts;
        - compile local declarations into canonical OPA JSON.

    Does NOT:
        - resolve inheritance;
        - calculate effective permissions;
        - merge with an existing data.json;
        - write files.
    """

    def __init__( self, data_mesh_file: str, security_groups_file: str, permission_depth_file: str):
        self.data_mesh_file = data_mesh_file
        self.security_groups_file = security_groups_file
        self.permission_depth_file = permission_depth_file

        self.data_mesh = load_json(data_mesh_file)
        self.security_groups = self._load_security_groups(security_groups_file)
        self.permission_depth = self._load_permission_depth( permission_depth_file )

        self.errors = []
        self.nodes = {}

    # ========================================================================
    # Public API
    # ========================================================================

    def compile(self, merged_tree: Dict[str, Any]) -> Dict[str, Any]:
        self.errors = []
        self.nodes = {}
        if not isinstance(merged_tree, dict):
            raise ValueError("merged permission tree must be an object")
        resource_values = merged_tree.get("resource_values", {})
        if not isinstance(resource_values, dict):
            raise ValueError( "merged tree resource_values must be an object" )
        self._build_resource_tree()
        try:
            self._compile_resource_values(resource_values)
        except ValueError as exc:
            self.errors.append(str(exc))
        if self.errors:
            raise ValueError( "Permission compilation failed:\n" + "\n".join( f"- {error}" for error in self.errors ) )
        return self._build_output()

    # ========================================================================
    # Data Mesh
    # ========================================================================

    def _build_resource_tree(self) -> None:
        structure = self.data_mesh.get( "dataMeshStructure", self.data_mesh)

        # --------------------------------------------------------------------
        # Dictionary-style Data Mesh
        #
        # Example:
        #
        # {
        #   "iceberg": {
        #       "hr": {
        #           "people": ["id", "name"]
        #       }
        #   }
        # }
        # --------------------------------------------------------------------
        if "catalogs" not in structure:
            if not isinstance(structure, dict):
                raise ValueError( "Invalid Data Mesh structure" )
            self.nodes["root"] = { "id": "root", "type": "root", "parent": None, "name": "root", "rules": {}}
            for catalog_name, catalog_data in structure.items():
                if not isinstance(catalog_data, dict):
                    continue
                self._add_catalog_dict( catalog_name, catalog_data)
            return

        # --------------------------------------------------------------------
        # List-style Data Mesh
        # --------------------------------------------------------------------
        catalogs = structure.get("catalogs", [])
        if not isinstance(catalogs, list):
            raise ValueError( "Invalid Data Mesh: 'catalogs' must be a list" )
        self.nodes["root"] = { "id": "root", "type": "root", "parent": None, "name": "root", "rules": {}}
        for catalog in catalogs:
            if not isinstance(catalog, dict):
                continue
            catalog_name = catalog.get("name")
            if not catalog_name:
                continue
            catalog_id = f"catalog/{catalog_name}"
            self._add_node( node_id=catalog_id, node_type="catalog", name=catalog_name, parent="root")
            for schema in catalog.get("schemas", []):
                if not isinstance(schema, dict):
                    continue
                schema_name = schema.get("name")
                if not schema_name:
                    continue
                schema_id = ( f"schema/{catalog_name}/{schema_name}" )
                self._add_node( node_id=schema_id, node_type="schema", name=schema_name, parent=catalog_id)
                for table in schema.get("tables", []):
                    if not isinstance(table, dict):
                        continue
                    table_name = table.get("name")
                    if not table_name:
                        continue
                    table_type = table.get("type", "table")
                    if table_type not in { "table", "view", "materialized_view"}:
                        table_type = "table"
                    table_id = ( f"{table_type}/" f"{catalog_name}/" f"{schema_name}/" f"{table_name}" )
                    self._add_node( node_id=table_id, node_type=table_type, name=table_name, parent=schema_id)
                    for column in table.get("columns", []):
                        if isinstance(column, str):
                            column_name = column
                        elif isinstance(column, dict):
                            column_name = str( column.get( "name", column.get("columnName", "")) ).strip()
                        else:
                            continue
                        if not column_name:
                            continue
                        column_id = ( f"column/" f"{catalog_name}/" f"{schema_name}/" f"{table_name}/" f"{column_name}" )
                        self._add_node( node_id=column_id, node_type="column", name=column_name, parent=table_id)

    def _add_catalog_dict( self, catalog_name: str, catalog_data: Dict[str, Any]) -> None:
        catalog_id = f"catalog/{catalog_name}"
        self._add_node( node_id=catalog_id, node_type="catalog", name=catalog_name, parent="root")
        for schema_name, schema_data in catalog_data.items():
            if not isinstance(schema_data, dict):
                continue
            schema_id = ( f"schema/{catalog_name}/{schema_name}" )

            self._add_node( node_id=schema_id, node_type="schema", name=schema_name, parent=catalog_id)
            for table_name, table_data in schema_data.items():
                if not isinstance(table_data, list):
                    continue
                table_id = ( f"table/" f"{catalog_name}/" f"{schema_name}/" f"{table_name}" )
                self._add_node( node_id=table_id, node_type="table", name=table_name, parent=schema_id)
                for column in table_data:
                    if isinstance(column, str):
                        column_name = column
                    elif isinstance(column, dict):
                        column_name = str( column.get("columnName", "") ).strip()
                    else:
                        continue
                    if not column_name:
                        continue
                    column_id = ( f"column/" f"{catalog_name}/" f"{schema_name}/" f"{table_name}/" f"{column_name}" )
                    self._add_node( node_id=column_id, node_type="column", name=column_name, parent=table_id)
    def _add_node( self, node_id: str, node_type: str, name: str, parent: Optional[str]) -> None:
        self.nodes[node_id] = { "id": node_id, "type": node_type, "parent": parent, "name": name, "rules": {}}

    # ========================================================================
    # Resource values
    # ========================================================================

    def _compile_resource_values( self, resource_values: Dict[str, Any]) -> None:
        # --------------------------------------------------------------------
        # Root
        # --------------------------------------------------------------------
        root_data = resource_values.get("root")
        if root_data is not None:
            if not isinstance(root_data, dict):
                raise ValueError( "resource_values.root must be an object" )
            root_node = self.nodes.get("root")
            if root_node is None:
                raise ValueError( "root does not exist in Data Mesh" )
            self._compile_node_rules( node=root_node, resource_data=root_data)

        # --------------------------------------------------------------------
        # Catalogs
        # --------------------------------------------------------------------
        catalogs = resource_values.get("catalogs", [])
        if not isinstance(catalogs, list):
            raise ValueError( "resource_values.catalogs must be a list" )
        for catalog_data in catalogs:
            if not isinstance(catalog_data, dict):
                raise ValueError( "catalog entry must be an object" )
            catalog_name = str( catalog_data.get("catalogName", "") ).strip()
            if not catalog_name:
                raise ValueError( "catalogName is missing" )
            catalog_id = f"catalog/{catalog_name}"
            catalog_node = self.nodes.get(catalog_id)
            if catalog_node is None:
                raise ValueError( "resource does not exist in Data Mesh: " f"catalog: {catalog_name}" )
            self._compile_node_rules( node=catalog_node, resource_data=catalog_data)
            schemas = catalog_data.get("schemas", [])
            if not isinstance(schemas, list):
                raise ValueError( f"schemas must be a list on catalog " f"{catalog_name!r}" )
            for schema_data in schemas:
                if not isinstance(schema_data, dict):
                    raise ValueError( "schema entry must be an object" )
                schema_name = str( schema_data.get("schemaName", "") ).strip()
                if not schema_name:
                    raise ValueError( f"schemaName is missing under " f"catalog {catalog_name!r}" )
                schema_id = ( f"schema/" f"{catalog_name}/" f"{schema_name}" )
                schema_node = self.nodes.get(schema_id)
                if schema_node is None:
                    raise ValueError( "resource does not exist in Data Mesh: " f"schema: {catalog_name}.{schema_name}" )
                self._compile_node_rules( node=schema_node, resource_data=schema_data)
                tables = schema_data.get("tables", [])
                if not isinstance(tables, list):
                    raise ValueError( f"tables must be a list on schema " f"{catalog_name}.{schema_name}" )
                for table_data in tables:
                    if not isinstance(table_data, dict):
                        raise ValueError( "table entry must be an object" )
                    table_name = str( table_data.get("tableName", "") ).strip()
                    if not table_name:
                        raise ValueError( "tableName is missing" )
                    table_node = self._find_table_node( catalog_name, schema_name, table_name)
                    if table_node is None:
                        raise ValueError( "resource does not exist in Data Mesh: " f"table: " f"{catalog_name}." f"{schema_name}." f"{table_name}" )
                    self._compile_node_rules( node=table_node, resource_data=table_data)
                    columns = table_data.get("columns", [])
                    if not isinstance(columns, list):
                        raise ValueError( f"columns must be a list on table " f"{catalog_name}." f"{schema_name}." f"{table_name}" )
                    for column_data in columns:
                        if isinstance(column_data, str):
                            column_name = column_data
                            column_data = { "columnName": column_name }
                        elif isinstance(column_data, dict):
                            column_name = str( column_data.get( "columnName", "") ).strip()
                        else:
                            raise ValueError( "column entry must be a string " "or object" )
                        if not column_name:
                            raise ValueError( "columnName is missing" )
                        column_id = ( f"column/" f"{catalog_name}/" f"{schema_name}/" f"{table_name}/" f"{column_name}" )
                        column_node = self.nodes.get(column_id)
                        if column_node is None:
                            raise ValueError( "resource does not exist in Data Mesh: " f"column: " f"{catalog_name}." f"{schema_name}." f"{table_name}." f"{column_name}" )
                        self._compile_node_rules( node=column_node, resource_data=column_data)

    # ========================================================================
    # Find table
    # ========================================================================

    def _find_table_node( self, catalog_name: str, schema_name: str, table_name: str) -> Optional[Dict[str, Any]]:
        for table_type in ( "table", "view", "materialized_view"):
            node_id = ( f"{table_type}/" f"{catalog_name}/" f"{schema_name}/" f"{table_name}" )
            node = self.nodes.get(node_id)
            if node is not None:
                return node
        return None

    # ========================================================================
    # Node rules
    # ========================================================================

    def _compile_node_rules( self, node: Dict[str, Any], resource_data: Dict[str, Any] ) -> None:

        permissions = resource_data.get("permissions", {})
        if not isinstance(permissions, dict):
            raise ValueError( f"permissions must be an object on {node['id']!r}" )

        # ========================================================================
        # Resource-level effects
        #
        # These are defined directly on the resource node:
        #
        # column:
        #   "column_masks": {
        #       "annual_salary": "'$$$'"
        #   }
        #
        # table:
        #   "row_filters": [
        #       "department = 'finance'"
        #   ]
        #
        # They are NOT stored inside permissions[group].
        # ========================================================================

        resource_column_masks = resource_data.get("column_masks", {})
        if not isinstance(resource_column_masks, dict):
            raise ValueError( f"column_masks must be an object on {node['id']!r}" )

        resource_row_filters = resource_data.get("row_filters", [])
        if not isinstance(resource_row_filters, list):
            raise ValueError( f"row_filters must be a list on {node['id']!r}" )

        # ========================================================================
        # Normal permissions
        # ========================================================================

        for group, group_rule in permissions.items():

            if not isinstance(group, str) or not group:
                raise ValueError( f"invalid security group on {node['id']!r}" )

            if not isinstance(group_rule, dict):
                raise ValueError( f"permissions for group {group!r} must be " f"an object on {node['id']!r}" )

            self._validate_security_group(group)

            allow = group_rule.get("allow", [])
            deny = group_rule.get("deny", [])

            if not isinstance(allow, list):
                raise ValueError( f"permissions.allow must be a list on " f"{node['id']!r} for {group!r}" )

            if not isinstance(deny, list):
                raise ValueError( f"permissions.deny must be a list on " f"{node['id']!r} for {group!r}" )

            conflict = set(allow) & set(deny)

            if conflict:
                raise ValueError( "permission appears in both allow and deny " f"on {node['id']!r} for {group!r}: " + ", ".join(sorted(conflict)) )

            # --------------------------------------------------------------------
            # Permissions
            # --------------------------------------------------------------------

            for permission in allow:
                self._compile_permission( node, permission, "allow", group )

            for permission in deny:
                self._compile_permission( node, permission, "deny", group )

            # --------------------------------------------------------------------
            # Row filter from permissions[group]
            #
            # Keep support for this representation too.
            # --------------------------------------------------------------------

            row_filter = group_rule.get("row_filter")

            if row_filter is not None:

                if not isinstance(row_filter, str):
                    raise ValueError( f"row_filter must be a string or null on " f"{node['id']!r} for {group!r}" )

                row_filter = row_filter.strip()

                if row_filter:
                    if node["type"] not in { "table", "view", "materialized_view" }:
                        raise ValueError( "row_filter must be attached to a " f"table/view: {node['id']!r}" )

                    self._validate_effect_depth( "GetRowFilters", node )

                    self._add_row_filter( node, group, row_filter )

        # ========================================================================
        # Resource-level row filters
        #
        # Example:
        #
        # "row_filters": [
        #     "department = 'finance'"
        # ]
        #
        # Apply the same filter to the security group(s) represented by the
        # permissions on this resource.
        # ========================================================================

        if resource_row_filters:

            if node["type"] not in { "table", "view", "materialized_view" }:
                raise ValueError( "row_filters must be attached to a " f"table/view: {node['id']!r}" )

            self._validate_effect_depth( "GetRowFilters", node )

            for group in permissions:

                for row_filter in resource_row_filters:

                    if not isinstance(row_filter, str):
                        raise ValueError( "row_filter expression must be a string" )

                    row_filter = row_filter.strip()

                    if not row_filter:
                        continue

                    self._add_row_filter( node, group, row_filter )

        # ========================================================================
        # Resource-level column masks
        #
        # Example:
        #
        # "column_masks": {
        #     "annual_salary": "'$$$'"
        # }
        #
        # These are attached directly to the column resource.
        # ========================================================================

        if resource_column_masks:

            if node["type"] != "column":
                raise ValueError( "column_masks must be attached to a " f"column: {node['id']!r}" )

            self._validate_effect_depth( "GetColumnMask", node )

            for column_name, expression in resource_column_masks.items():

                column_name = str(column_name).strip()

                if not column_name:
                    raise ValueError( "column mask requires column" )

                if not isinstance(expression, str):
                    raise ValueError( "column mask expression must be a string" )

                expression = expression.strip()

                if not expression:
                    raise ValueError( "column mask requires expression" )

                if node["name"] != column_name:
                    raise ValueError( f"column mask targets {column_name!r}, " f"but is attached to {node['name']!r}" )

                # Apply the mask to every group defined on this resource.
                for group in permissions:
                    self._add_column_mask( node, group, column_name, expression )

                    # The mask itself requires GetColumnMask.
                    rule = node["rules"].setdefault( group, { "allow": [], "deny": [], "row_filter": None, "column_masks": {} } )

                    if "GetColumnMask" not in rule["allow"]:
                        rule["allow"].append("GetColumnMask")

        # ========================================================================
        # Resource-level row-filter permission
        # ========================================================================

        if resource_row_filters:

            for group in permissions:

                rule = node["rules"].setdefault( group, { "allow": [], "deny": [], "row_filter": None, "column_masks": {} } )

                if "GetRowFilters" not in rule["allow"]:
                    rule["allow"].append("GetRowFilters")

    # ========================================================================
    # Security groups
    # ========================================================================

    def _validate_security_group(self, group: str) -> None:
        groups = self.security_groups
        if isinstance(groups, list):
            known_groups = set(groups)
        elif isinstance(groups, dict):
            if isinstance( groups.get("security_groups"), list):
                known_groups = set( groups["security_groups"] )
            elif isinstance( groups.get("groups"), list):
                known_groups = set( groups["groups"] )
            else:
                # Supports:
                #
                # {
                #     "hr_manager": {...},
                #     "finance_manager": {...}
                # }
                known_groups = set(groups.keys())
        else:
            raise ValueError( "security_groups.json must contain " "a list or object" )
        if group not in known_groups:
            raise ValueError( f"unknown security group {group!r}" )

    # ========================================================================
    # Permission depth
    # ========================================================================

    def _compile_permission( self, node: Dict[str, Any], permission: str, effect: str, group: str) -> None:
        if not isinstance(permission, str):
            raise ValueError( f"permission must be a string on " f"{node['id']!r}" )
        if permission not in self.permission_depth:
            raise ValueError( f"permission {permission!r} has no entry " "in permission_depth.json" )
        permission_depth = self.permission_depth[permission]
        target_depth = RESOURCE_DEPTH[node["type"]]
        if target_depth > permission_depth:
            raise ValueError( f"permission {permission!r} is placed at " f"depth {target_depth}, but its maximum " f"allowed depth is {permission_depth}" )

        self._set_permission( node, permission, effect, group)

    def _validate_effect_depth( self, permission: str, node: Dict[str, Any]) -> None:
        if permission not in self.permission_depth:
            raise ValueError( f"permission {permission!r} has no entry " "in permission_depth.json" )
        target_depth = RESOURCE_DEPTH[node["type"]]
        maximum_depth = self.permission_depth[permission]
        if target_depth > maximum_depth:
            raise ValueError( f"permission {permission!r} is placed at " f"depth {target_depth}, but its maximum " f"allowed depth is {maximum_depth}" )

    # ========================================================================
    # Local permission declarations
    # ========================================================================

    def _set_permission( self, node: Dict[str, Any], permission: str, effect: str, group: str) -> None:
        rule = node["rules"].setdefault( group, { "allow": [], "deny": [], "row_filter": None, "column_masks": {}})
        opposite = ( "deny" if effect == "allow" else "allow" )
        if permission in rule[opposite]:
            raise ValueError( f"conflicting local declarations for " f"{permission!r} on {node['id']!r} " f"for {group!r}" )
        if permission not in rule[effect]:
            rule[effect].append(permission)

    def _add_row_filter( self, node: Dict[str, Any], group: str, expression: str) -> None:
        rule = node["rules"].setdefault( group, { "allow": [], "deny": [], "row_filter": None, "column_masks": {}})
        existing = rule.get("row_filter")
        if existing is None:
            rule["row_filter"] = expression
        elif existing != expression:
            raise ValueError( f"multiple different row filters defined for " f"{node['id']!r} and {group!r}" )

    def _add_column_mask( self, node: Dict[str, Any], group: str, column_name: str, expression: str) -> None:
        rule = node["rules"].setdefault( group, { "allow": [], "deny": [], "row_filter": None, "column_masks": {}})
        masks = rule["column_masks"]
        if column_name in masks:
            if masks[column_name] != expression:
                raise ValueError( f"multiple different column masks " f"defined for {column_name!r} " f"on {node['id']!r} " f"for {group!r}" )

        masks[column_name] = expression

    # ========================================================================
    # Output
    # ========================================================================

    def _build_output(self) -> Dict[str, Any]:
        rules = {}
        for node in self.nodes.values():
            if not node["rules"]:
                continue
            resource_id = self._output_resource_id(node)
            rules[resource_id] = {}
            for group, rule in node["rules"].items():
                rules[resource_id][group] = {
                    "rule_id": self._make_rule_id( resource_id, group),
                    "group": group,
                    "resource_type": node["type"],
                    "permissions": { "allow": sorted( set(rule.get("allow", [])) ), "deny": sorted( set(rule.get("deny", [])) )},
                    "row_filter": rule.get( "row_filter" ),
                    "column_masks": dict( rule.get( "column_masks", {}) ),
                }

        return { "version": "2.0-opa", "rules": rules}

    # ========================================================================
    # Helpers
    # ========================================================================

    @staticmethod
    def _output_resource_id( node: Dict[str, Any]) -> str:
        if node["type"] == "root":
            return "root"
        parts = node["id"].split("/")
        return "root/" + "/".join(parts[1:])

    @staticmethod
    def _make_rule_id( resource_id: str, group: str) -> str:
        safe_resource = ( resource_id .replace("/", "_") .replace("-", "_") )
        safe_group = ( group .replace("/", "_") .replace("-", "_") )
        return f"rule_{safe_resource}_{safe_group}"

    @classmethod
    def _load_security_groups( cls, path: str) -> Any:
        data = load_json(path)
        if not isinstance(data, (list, dict)):
            raise ValueError( "security_groups.json must contain " "a list or object" )

        return data

    @classmethod
    def _load_permission_depth( cls, path: str) -> Dict[str, int]:

        data = load_json(path)

        if not isinstance(data, dict):
            raise ValueError( "permission_depth.json must contain " "an object" )

        permission_depth = data.get( "permission_depth" )
        if permission_depth is None:
            permission_depth = data
        if not isinstance(permission_depth, dict):
            raise ValueError( "permission_depth.json must contain " "a permission-depth object" )
        result = {}

        for permission, depth in permission_depth.items():
            if not isinstance(depth, int):
                raise ValueError( f"Invalid depth for permission " f"{permission!r}: {depth!r}" )
            if depth < 0 or depth > 4:
                raise ValueError( f"Invalid depth for permission " f"{permission!r}: {depth}" )
            result[permission] = depth
        return result
