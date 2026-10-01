from copy import deepcopy
from typing import Any, Dict, List

class PermissionTreeMerger:
    """
    Merge extracted permission-tree structures.

    The merged tree stores permissions per security group at
    every resource level:

        "permissions": {
            "hr_manager": {
                "allow": [...],
                "deny": [...],
                "row_filter": ...,
                "column_masks": {...}
            }
        }

    The security group is taken from:

        new["subject_value"]
    """
    def merge( self, existing: Dict[str, Any], new: Dict[str, Any] ) -> Dict[str, Any]:

        if not isinstance(existing, dict):
            raise ValueError("existing permission tree must be an object")

        if not isinstance(new, dict):
            raise ValueError("new permission tree must be an object")

        group = new.get("subject_value")
        if not group:
            raise ValueError("new permission tree is missing subject_value")

        result = deepcopy(existing)
        result.setdefault("resource_values", {})

        row_filters = new.get("row_filters", [])
        column_masks = new.get("column_masks", [])

        # First merge: initialize the cumulative tree with the
        # same metadata and normalized resource structure.
        if not existing:
            result = { "subject_attribute": new.get("subject_attribute"), "subject_value": group, "resource_type": new.get("resource_type"), "resource_values": {} }

            self._merge_resource_values( result["resource_values"], new.get("resource_values", {}), group=group, row_filters=row_filters, column_masks=column_masks)

            return result

        self._merge_resource_values( result["resource_values"], new.get("resource_values", {}), group=group, row_filters=row_filters, column_masks=column_masks)

        return result

    # ========================================================================
    # Normalize metadata visibility filters
    # ========================================================================

    def _merge_visibility_filters(
            self,
            existing: Dict[str, Any],
            new: Dict[str, Any]
    ) -> None:

        filter_mapping = {
            "FilterCatalogs": "filter_catalogs",
            "FilterSchemas": "filter_schemas",
            "FilterTables": "filter_tables",
            "FilterColumns": "filter_columns",
        }

        for input_key, canonical_key in filter_mapping.items():

            # Existing canonical values
            current = existing.get(canonical_key, [])

            if not isinstance(current, list):
                current = []

            current = set(
                value for value in current if value
            )

            # Existing old-style values
            old_values = existing.get(input_key)

            if isinstance(old_values, list):
                current.update(
                    value for value in old_values if value
                )

            # New declaration
            new_filter = new.get(input_key)

            if isinstance(new_filter, dict):

                allowed = new_filter.get("allowed", [])
                deny = new_filter.get("deny", [])

                if not isinstance(allowed, list):
                    allowed = []

                if not isinstance(deny, list):
                    deny = []

                for value in allowed:
                    if value:
                        current.discard(value)

                for value in deny:
                    if value:
                        current.add(value)

            elif isinstance(new_filter, list):

                current.update(
                    value for value in new_filter if value
                )

            # Write ONLY canonical representation
            existing[canonical_key] = sorted(current)

            # Delete legacy representation
            existing.pop(input_key, None)

    # ========================================================================
    # Metadata visibility filters
    # ========================================================================

    def _merge_visibility_filters(
            self,
            existing: Dict[str, Any],
            new: Dict[str, Any]
    ) -> None:
        """
        Merge metadata visibility filters into the canonical representation.

        Canonical representation:

            "filter_catalogs": [...]
            "filter_schemas": [...]
            "filter_tables": [...]
            "filter_columns": [...]

        Input representation may be either:

            "FilterSchemas": {
                "allowed": [],
                "deny": ["hr"]
            }

        or:

            "FilterSchemas": ["hr"]

        Semantics:
            allowed -> remove from hidden list
            deny    -> add to hidden list
        """

        filter_mapping = {
            "FilterCatalogs": "filter_catalogs",
            "FilterSchemas": "filter_schemas",
            "FilterTables": "filter_tables",
            "FilterColumns": "filter_columns",
        }

        for input_key, canonical_key in filter_mapping.items():

            new_filter = new.get(input_key)

            if new_filter is None:
                continue

            current = existing.get(canonical_key, [])

            if not isinstance(current, list):
                current = []

            current = set(current)

            # ------------------------------------------------------------
            # New representation:
            #
            # "FilterSchemas": {
            #     "allowed": [...],
            #     "deny": [...]
            # }
            # ------------------------------------------------------------
            if isinstance(new_filter, dict):

                allowed = new_filter.get("allowed", [])
                deny = new_filter.get("deny", [])

                if not isinstance(allowed, list):
                    allowed = []

                if not isinstance(deny, list):
                    deny = []

                # ALLOW removes the value from the hidden list.
                for value in allowed:
                    if value:
                        current.discard(value)

                # DENY adds the value to the hidden list.
                # DENY wins if it also appears in allowed.
                for value in deny:
                    if value:
                        current.add(value)

            # ------------------------------------------------------------
            # Already-normalized representation:
            #
            # "FilterSchemas": ["hr"]
            # ------------------------------------------------------------
            elif isinstance(new_filter, list):

                for value in new_filter:
                    if value:
                        current.add(value)

            # ------------------------------------------------------------
            # Ignore malformed values
            # ------------------------------------------------------------
            else:
                continue

            existing[canonical_key] = sorted(current)

            # IMPORTANT:
            # Never leave the old camel-case representation in the tree.
            existing.pop(input_key, None)


    # ========================================================================
    # Resource values
    # ========================================================================

    def _merge_resource_values( self, existing: Dict[str, Any], new: Dict[str, Any], group: str, row_filters: List[Any], column_masks: List[Any]) -> None:
        # --------------------------------------------------------------------
        # Root
        # --------------------------------------------------------------------
        if "root" in new:
            if "root" not in existing:
                existing["root"] = deepcopy(new["root"])
                self._normalize_new_resource( existing["root"], group, row_filters=[], column_masks=[])
            else:
                self._merge_resource( existing["root"], new["root"], group=group, row_filters=[], column_masks=[])

        # --------------------------------------------------------------------
        # Catalogs
        # --------------------------------------------------------------------
        new_catalogs = new.get("catalogs", [])
        if not isinstance(new_catalogs, list):
            raise ValueError("new resource_values.catalogs must be a list")
        existing_catalogs = existing.setdefault("catalogs", [])
        for new_catalog in new_catalogs:
            if not isinstance(new_catalog, dict):
                continue
            catalog_name = new_catalog.get("catalogName")
            if not catalog_name:
                continue
            existing_catalog = self._find_by_name( existing_catalogs, "catalogName", catalog_name)
            if existing_catalog is None:
                existing_catalog = deepcopy(new_catalog)
                # IMPORTANT:
                # Normalize the catalog AND all nested schemas/tables/columns.
                self._normalize_resource_tree( existing_catalog, group, row_filters=row_filters, column_masks=column_masks)
                existing_catalogs.append(existing_catalog)
            else:
                self._merge_catalog( existing_catalog, new_catalog, group=group, row_filters=row_filters, column_masks=column_masks)

    # ========================================================================
    # Catalog
    # ========================================================================
    def _merge_catalog( self, existing: Dict[str, Any], new: Dict[str, Any], group: str, row_filters: List[Any], column_masks: List[Any]) -> None:
        self._merge_resource( existing, new, group=group, row_filters=[], column_masks=[])
        existing_schemas = existing.setdefault("schemas", [])
        new_schemas = new.get("schemas", [])
        if not isinstance(new_schemas, list):
            return
        for new_schema in new_schemas:
            if not isinstance(new_schema, dict):
                continue
            schema_name = new_schema.get("schemaName")
            if not schema_name:
                continue
            existing_schema = self._find_by_name( existing_schemas, "schemaName", schema_name)
            if existing_schema is None:
                existing_schema = deepcopy(new_schema)
                # Normalize schema AND nested tables/columns.
                self._normalize_resource_tree( existing_schema, group, row_filters=row_filters, column_masks=column_masks)
                existing_schemas.append(existing_schema)
            else:
                self._merge_schema( existing_schema, new_schema, group=group, row_filters=row_filters, column_masks=column_masks)
    # ========================================================================
    # Schema
    # ========================================================================
    def _merge_schema( self, existing: Dict[str, Any], new: Dict[str, Any], group: str, row_filters: List[Any], column_masks: List[Any]) -> None:
        self._merge_resource( existing, new, group=group, row_filters=row_filters, column_masks=column_masks)
        existing_tables = existing.setdefault("tables", [])
        new_tables = new.get("tables", [])
        if not isinstance(new_tables, list):
            return
        for new_table in new_tables:
            if not isinstance(new_table, dict):
                continue
            table_name = new_table.get("tableName")
            if not table_name:
                continue
            existing_table = self._find_by_name( existing_tables, "tableName", table_name)
            if existing_table is None:
                existing_table = deepcopy(new_table)
                self._normalize_resource_tree( existing_table, group, row_filters=row_filters, column_masks=column_masks)
                existing_tables.append(existing_table)
            else:
                self._merge_table( existing_table, new_table, group=group, row_filters=row_filters, column_masks=column_masks)

    # ========================================================================
    # Table
    # ========================================================================

    def _merge_table( self, existing: Dict[str, Any], new: Dict[str, Any], group: str, row_filters: List[Any], column_masks: List[Any]) -> None:
        self._merge_resource( existing, new, group=group, row_filters=row_filters, column_masks=column_masks)
        existing_columns = existing.setdefault("columns", [])
        new_columns = new.get("columns", [])
        if not isinstance(new_columns, list):
            return
        for new_column in new_columns:
            if isinstance(new_column, str):
                column_name = new_column
                new_column = {"columnName": column_name}
            elif isinstance(new_column, dict):
                column_name = new_column.get("columnName")
            else:
                continue
            if not column_name:
                continue
            existing_column = self._find_by_name( existing_columns, "columnName", column_name)
            if existing_column is None:
                existing_column = deepcopy(new_column)
                self._normalize_new_resource( existing_column, group, row_filters=[], column_masks=[])
                existing_columns.append(existing_column)
            else:
                self._merge_resource( existing_column, new_column, group=group, row_filters=[], column_masks=[])

    # ========================================================================
    # Resource declarations
    # ========================================================================

    def _merge_resource( self, existing: Dict[str, Any], new: Dict[str, Any], group: str, row_filters: List[Any], column_masks: List[Any]) -> None:
        existing_permissions = existing.setdefault("permissions", {})
        if not isinstance(existing_permissions, dict):
            raise ValueError("resource permissions must be an object")

        # --------------------------------------------------------------------
        # Convert old/simple structure:
        #
        # {
        #     "permissions": {
        #         "allow": [...],
        #         "deny": [...]
        #     }
        # }
        #
        # into:
        #
        # {
        #     "permissions": {
        #         "<group>": {
        #             "allow": [...],
        #             "deny": [...]
        #         }
        #     }
        # }
        # --------------------------------------------------------------------
        if "allow" in existing_permissions or "deny" in existing_permissions:
            old_allow = existing_permissions.pop("allow", [])
            old_deny = existing_permissions.pop("deny", [])
            if group not in existing_permissions:
                existing_permissions[group] = { "allow": list(old_allow or []), "deny": list(old_deny or []), "row_filter": None, "column_masks": {}}
        group_permissions = existing_permissions.setdefault( group, { "allow": [], "deny": [], "row_filter": None, "column_masks": {}})
        if not isinstance(group_permissions, dict):
            raise ValueError( f"permissions for group {group!r} must be an object" )

        # --------------------------------------------------------------------
        # New permissions
        # --------------------------------------------------------------------
        new_permissions = new.get("permissions", {})
        if not isinstance(new_permissions, dict):
            new_permissions = {}

        new_allow = set(new_permissions.get("allow", []))
        new_deny = set(new_permissions.get("deny", []))

        allow = set(group_permissions.get("allow", []))
        deny = set(group_permissions.get("deny", []))

        # ALLOW overrides DENY.
        for permission in new_allow:
            deny.discard(permission)
            allow.add(permission)

        # DENY overrides ALLOW.
        for permission in new_deny:
            allow.discard(permission)
            deny.add(permission)

        group_permissions["allow"] = sorted(allow)
        group_permissions["deny"] = sorted(deny)


        # --------------------------------------------------------------------
        # Metadata visibility filters
        # --------------------------------------------------------------------
        self._merge_visibility_filters(existing, new)


        # --------------------------------------------------------------------
        # Row filters
        # --------------------------------------------------------------------
        self._merge_row_filters( group_permissions, row_filters, new)

        # --------------------------------------------------------------------
        # Column masks
        # --------------------------------------------------------------------
        self._merge_column_masks( group_permissions, column_masks, new)

    # ========================================================================
    # Normalize a single newly inserted resource
    # ========================================================================

    def _normalize_new_resource(
            self,
            resource: Dict[str, Any],
            group: str,
            row_filters: List[Any],
            column_masks: List[Any]
    ) -> None:

        # ------------------------------------------------------------
        # Metadata visibility filters
        # ------------------------------------------------------------
        self._normalize_visibility_filters(resource)

        old_permissions = resource.get("permissions")

        # No permissions declared on this resource.
        if old_permissions is None:
            resource["permissions"] = {
                group: {
                    "allow": [],
                    "deny": [],
                    "row_filter": None,
                    "column_masks": {}
                }
            }
            return

        # Existing simple structure.
        if (
                isinstance(old_permissions, dict)
                and (
                "allow" in old_permissions
                or "deny" in old_permissions
        )
        ):
            resource["permissions"] = {
                group: {
                    "allow": list(old_permissions.get("allow", [])),
                    "deny": list(old_permissions.get("deny", [])),
                    "row_filter": None,
                    "column_masks": {}
                }
            }
            return

        # Permissions exists but is not an object.
        if not isinstance(old_permissions, dict):
            resource["permissions"] = {
                group: {
                    "allow": [],
                    "deny": [],
                    "row_filter": None,
                    "column_masks": {}
                }
            }
            return

        # Already group-based structure.
        if group not in old_permissions:
            old_permissions[group] = {
                "allow": [],
                "deny": [],
                "row_filter": None,
                "column_masks": {}
            }

    # ========================================================================
    # Normalize an entire resource subtree
    # ========================================================================

    def _normalize_resource_tree( self, resource: Dict[str, Any], group: str, row_filters: List[Any], column_masks: List[Any]) -> None:
        """
        Normalize a newly inserted resource and all descendants.

        This is required because deepcopy(new_catalog) also copies
        its schemas, tables and columns without passing through the
        individual merge functions.
        """
        self._normalize_new_resource( resource, group, row_filters=row_filters, column_masks=column_masks)

        # ------------------------------------------------------------
        # Schemas
        # ------------------------------------------------------------
        schemas = resource.get("schemas", [])
        if isinstance(schemas, list):
            for schema in schemas:
                if not isinstance(schema, dict):
                    continue
                self._normalize_resource_tree( schema, group, row_filters=row_filters, column_masks=column_masks)

        # ------------------------------------------------------------
        # Tables
        # ------------------------------------------------------------
        tables = resource.get("tables", [])
        if isinstance(tables, list):
            for table in tables:
                if not isinstance(table, dict):
                    continue
                self._normalize_resource_tree( table, group, row_filters=row_filters, column_masks=column_masks)

        # ------------------------------------------------------------
        # Columns
        # ------------------------------------------------------------
        columns = resource.get("columns", [])
        if isinstance(columns, list):
            for column in columns:
                if isinstance(column, str):
                    index = columns.index(column)
                    column = { "columnName": column, "permissions": {}}
                    columns[index] = column
                if not isinstance(column, dict):
                    continue
                self._normalize_new_resource( column, group, row_filters=[], column_masks=[])

    # ========================================================================
    # Row filters
    # ========================================================================

    def _merge_row_filters( self, group_permissions: Dict[str, Any], row_filters: List[Any], new_resource: Dict[str, Any]) -> None:
        expressions = []
        if isinstance(row_filters, list):
            expressions.extend(row_filters)
        resource_filters = new_resource.get("row_filters", [])
        if isinstance(resource_filters, list):
            expressions.extend(resource_filters)
        new_group_rule = new_resource.get("permissions", {})
        if isinstance(new_group_rule, dict):
            local_filter = new_group_rule.get("row_filter")
            if local_filter:
                expressions.append(local_filter)
        expressions = [ expression for expression in expressions if expression ]
        if not expressions:
            return
        existing_filter = group_permissions.get("row_filter")
        for expression in expressions:
            if existing_filter is None:
                group_permissions["row_filter"] = expression
                existing_filter = expression
            elif existing_filter != expression:
                group_permissions["row_filter"] = ( f"({existing_filter}) AND ({expression})" )
                existing_filter = group_permissions["row_filter"]

    # ========================================================================
    # Column masks
    # ========================================================================

    def _merge_column_masks( self, group_permissions: Dict[str, Any], column_masks: List[Any], new_resource: Dict[str, Any]) -> None:
        masks = group_permissions.setdefault("column_masks", {})
        if not isinstance(masks, dict):
            masks = {}
            group_permissions["column_masks"] = masks
        new_masks = []
        if isinstance(column_masks, list):
            new_masks.extend(column_masks)
        resource_masks = new_resource.get("column_masks", [])
        if isinstance(resource_masks, list):
            new_masks.extend(resource_masks)
        for new_mask in new_masks:
            if not isinstance(new_mask, dict):
                continue
            column = new_mask.get("column")
            if not column:
                continue
            expression = new_mask.get("expression")
            if column not in masks:
                masks[column] = expression
            else:
                old_expression = masks[column]
                if ( old_expression is not None and expression is not None and old_expression != expression ):
                    raise ValueError( f"Conflicting column masks for column {column!r}" )

    # ========================================================================
    # Helpers
    # ========================================================================

    @staticmethod
    def _find_by_name( items: List[Dict[str, Any]], field: str, value: str) -> Any:
        for item in items:
            if ( isinstance(item, dict) and item.get(field) == value ):
                return item

        return None
