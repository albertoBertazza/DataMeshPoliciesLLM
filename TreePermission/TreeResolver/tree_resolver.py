import json
from typing import Any, Dict, List, Optional


class PermissionTreeResolver:
    """
    Resolver for the hierarchical permission tree.

    Supported tree structure:

        ROOT
        ├── security_groups
        │   └── <security_group>
        │
        └── catalogs
            └── <catalog>
                ├── security_groups
                │   └── <security_group>
                └── schemas
                    └── <schema>
                        ├── security_groups
                        │   └── <security_group>
                        └── tables
                            └── <table>
                                ├── security_groups
                                │   └── <security_group>
                                └── columns
                                    └── <column>
                                        └── security_groups
                                            └── <security_group>

    Resource collections are dictionaries:

        "catalogs": {
            "iceberg": {...}
        }

        "schemas": {
            "hr": {...}
        }

        "tables": {
            "employees": {...}
        }

        "columns": {
            "attrition": {...}
        }

    allowed_actions can be either:

        "allowed_actions": [
            "SelectFromTableAction"
        ]

    or:

        "allowed_actions": {
            "SelectFromTableAction": {
                "allowed": true,
                "missing": []
            }
        }

    permissions:

        "permissions": ["*"]

    means that the security group has global access.
    """

    RESOURCE_KEYS = ("catalogs", "schemas", "tables", "columns")
    LEVELS = ("root", "catalog", "schema", "table")

    def __init__(self, tree: Dict[str, Any]):
        if not isinstance(tree, dict):
            raise ValueError("Permission tree must be a dictionary.")

        self.tree = tree
        self.root = tree.get("ROOT", {})

        if not isinstance(self.root, dict):
            raise ValueError("tree.json ROOT must be an object.")

    # ========================================================================
    # Generic helpers
    # ========================================================================

    @staticmethod
    def _security_group_node(
        node: Optional[Dict[str, Any]],
        security_group: str,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(node, dict):
            return None

        security_groups = node.get("security_groups", {})

        if not isinstance(security_groups, dict):
            return None

        group_node = security_groups.get(security_group)

        if not isinstance(group_node, dict):
            return None

        return group_node

    @staticmethod
    def _permissions(node: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(node, dict):
            return []

        permissions = node.get("permissions", [])

        if not isinstance(permissions, list):
            return []

        return permissions

    @staticmethod
    def _is_global(node: Optional[Dict[str, Any]]) -> bool:
        return "*" in PermissionTreeResolver._permissions(node)

    @staticmethod
    def _allowed_actions(node: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(node, dict):
            return []

        actions = node.get("allowed_actions", [])

        if isinstance(actions, dict):
            return sorted(actions.keys())

        if isinstance(actions, list):
            return actions

        return []

    @staticmethod
    def _allowed_action_data(
        node: Optional[Dict[str, Any]],
        action: str,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(node, dict):
            return None

        actions = node.get("allowed_actions", {})

        if not isinstance(actions, dict):
            return None

        action_data = actions.get(action)

        if not isinstance(action_data, dict):
            return None

        return action_data

    @staticmethod
    def _find_resource(
        nodes: Any,
        key: str,
        value: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Find a resource in either supported representation.

        Dictionary:

            {
                "iceberg": {...}
            }

        List:

            [
                {
                    "catalog": "iceberg",
                    ...
                }
            ]
        """

        if isinstance(nodes, dict):
            node = nodes.get(value)

            if isinstance(node, dict):
                return node

            return None

        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict) and node.get(key) == value:
                    return node

        return None

    @staticmethod
    def _iter_children(nodes: Any):
        """
        Iterate over resources regardless of whether the collection is a
        dictionary or a list.
        """

        if isinstance(nodes, dict):
            for node in nodes.values():
                if isinstance(node, dict):
                    yield node

        elif isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    yield node

    # ========================================================================
    # Security groups
    # ========================================================================

    def security_groups(self) -> List[str]:
        groups = set()

        def collect(node: Any):
            if not isinstance(node, dict):
                return

            security_groups = node.get("security_groups", {})

            if isinstance(security_groups, dict):
                groups.update(security_groups.keys())

            for key in self.RESOURCE_KEYS:
                nodes = node.get(key, {})

                for child in self._iter_children(nodes):
                    collect(child)

        collect(self.root)

        return sorted(groups)

    # ========================================================================
    # Catalog
    # ========================================================================

    def catalog_node(self, catalog: str) -> Optional[Dict[str, Any]]:
        return self._find_resource(
            self.root.get("catalogs", {}),
            "catalog",
            catalog,
        )

    def catalog_security_group(
        self,
        security_group: str,
        catalog: str,
    ) -> Optional[Dict[str, Any]]:
        return self._security_group_node(
            self.catalog_node(catalog),
            security_group,
        )

    # ========================================================================
    # Schema
    # ========================================================================

    def schema_node(
        self,
        catalog: str,
        schema: str,
    ) -> Optional[Dict[str, Any]]:
        catalog_node = self.catalog_node(catalog)

        if not catalog_node:
            return None

        return self._find_resource(
            catalog_node.get("schemas", {}),
            "schema",
            schema,
        )

    def schema_security_group(
        self,
        security_group: str,
        catalog: str,
        schema: str,
    ) -> Optional[Dict[str, Any]]:
        return self._security_group_node(
            self.schema_node(catalog, schema),
            security_group,
        )

    # ========================================================================
    # Table
    # ========================================================================

    def table_node(
        self,
        catalog: str,
        schema: str,
        table: str,
    ) -> Optional[Dict[str, Any]]:
        schema_node = self.schema_node(catalog, schema)

        if not schema_node:
            return None

        return self._find_resource(
            schema_node.get("tables", {}),
            "table",
            table,
        )

    def table_security_group(
        self,
        security_group: str,
        catalog: str,
        schema: str,
        table: str,
    ) -> Optional[Dict[str, Any]]:
        return self._security_group_node(
            self.table_node(catalog, schema, table),
            security_group,
        )

    # ========================================================================
    # Column
    # ========================================================================

    def column_node(
        self,
        catalog: str,
        schema: str,
        table: str,
        column: str,
    ) -> Optional[Dict[str, Any]]:
        table_node = self.table_node(catalog, schema, table)

        if not table_node:
            return None

        return self._find_resource(
            table_node.get("columns", {}),
            "column",
            column,
        )

    def column_security_group(
        self,
        security_group: str,
        catalog: str,
        schema: str,
        table: str,
        column: str,
    ) -> Optional[Dict[str, Any]]:
        return self._security_group_node(
            self.column_node(catalog, schema, table, column),
            security_group,
        )

    # ========================================================================
    # Path resolution
    # ========================================================================

    def resolve_path(
        self,
        security_group: str,
        catalog: str,
        schema: str,
        table: Optional[str] = None,
    ) -> Dict[str, Optional[Dict[str, Any]]]:

        result = {
            "root": self._security_group_node(
                self.root,
                security_group,
            ),
            "catalog": self.catalog_security_group(
                security_group,
                catalog,
            ),
            "schema": self.schema_security_group(
                security_group,
                catalog,
                schema,
            ),
            "table": None,
        }

        if table is not None:
            result["table"] = self.table_security_group(
                security_group,
                catalog,
                schema,
                table,
            )

        return result

    # ========================================================================
    # Effective permissions
    # ========================================================================

    def effective_permissions(
        self,
        security_group: str,
        catalog: str,
        schema: str,
        table: Optional[str] = None,
    ) -> Dict[str, List[str]]:

        path = self.resolve_path(
            security_group,
            catalog,
            schema,
            table,
        )

        result = {
            "root": [],
            "catalog": [],
            "schema": [],
            "table": [],
            "effective": [],
        }

        effective = set()

        for level in self.LEVELS:
            node = path.get(level)

            permissions = self._permissions(node)

            result[level] = permissions

            effective.update(permissions)

        result["effective"] = sorted(effective)

        return result

    # ========================================================================
    # Effective allowed actions
    # ========================================================================

    def effective_allowed_actions(
        self,
        security_group: str,
        catalog: str,
        schema: str,
        table: Optional[str] = None,
    ) -> Dict[str, Any]:

        path = self.resolve_path(
            security_group,
            catalog,
            schema,
            table,
        )

        effective_actions = set()
        source = {}
        action_data = {}

        global_allow_all = False

        for level in self.LEVELS:
            node = path.get(level)

            if node is None:
                continue

            # permissions: ["*"] means global access.
            if self._is_global(node):
                global_allow_all = True
                source["*"] = level

            actions = self._allowed_actions(node)

            for action in actions:
                if action == "*":
                    global_allow_all = True
                    source["*"] = level
                    continue

                effective_actions.add(action)

                # More specific levels override the source.
                source[action] = level

                data = self._allowed_action_data(
                    node,
                    action,
                )

                if data is not None:
                    action_data[action] = data

        return {
            "global_allow_all": global_allow_all,
            "actions": sorted(effective_actions),
            "source": source,
            "action_data": action_data,
        }

    # ========================================================================
    # Action resolution
    # ========================================================================

    def resolve_action(
        self,
        security_group: str,
        catalog: str,
        schema: str,
        table: str,
        action: str,
    ) -> Dict[str, Any]:

        path = self.resolve_path(
            security_group,
            catalog,
            schema,
            table,
        )

        # More specific resources take precedence.
        for level in ("table", "schema", "catalog", "root"):
            node = path.get(level)

            if node is None:
                continue

            # permissions: ["*"] means unrestricted access.
            if self._is_global(node):
                return {
                    "allowed": True,
                    "source": level,
                    "action": action,
                    "action_data": {
                        "global": True,
                    },
                    "permissions": self._permissions(node),
                }

            actions = self._allowed_actions(node)

            # Explicit wildcard in allowed_actions.
            if "*" in actions:
                return {
                    "allowed": True,
                    "source": level,
                    "action": action,
                    "action_data": {
                        "global": True,
                    },
                    "permissions": self._permissions(node),
                }

            if action in actions:
                return {
                    "allowed": True,
                    "source": level,
                    "action": action,
                    "action_data": self._allowed_action_data(
                        node,
                        action,
                    ),
                    "permissions": self._permissions(node),
                }

        return {
            "allowed": False,
            "source": None,
            "action": action,
            "action_data": None,
            "permissions": [],
        }

    # ========================================================================
    # Column filters
    # ========================================================================

    def column_filters(
        self,
        security_group: str,
        catalog: str,
        schema: str,
        table: str,
        column: str,
    ) -> Dict[str, Any]:

        node = self.column_security_group(
            security_group,
            catalog,
            schema,
            table,
            column,
        )

        if not node:
            return {}

        filters = node.get("filters", {})

        if not isinstance(filters, dict):
            return {}

        return filters

    # ========================================================================
    # Specific filter
    # ========================================================================

    def get_column_mask(
        self,
        security_group: str,
        catalog: str,
        schema: str,
        table: str,
        column: str,
    ) -> List[Dict[str, Any]]:

        filters = self.column_filters(
            security_group,
            catalog,
            schema,
            table,
            column,
        )

        masks = filters.get("GetColumnMask", [])

        if not isinstance(masks, list):
            return []

        return masks

    # ========================================================================
    # Actions present in tree
    # ========================================================================

    def collect_allowed_actions(self) -> List[str]:
        actions = set()

        def collect(node: Any):
            if not isinstance(node, dict):
                return

            security_groups = node.get("security_groups", {})

            if isinstance(security_groups, dict):
                for group_node in security_groups.values():
                    actions.update(
                        self._allowed_actions(group_node)
                    )

            for key in self.RESOURCE_KEYS:
                nodes = node.get(key, {})

                for child in self._iter_children(nodes):
                    collect(child)

        collect(self.root)

        return sorted(
            action
            for action in actions
            if action != "*"
        )


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":

    with open(
        "../output/permission_tree.json",
        "r",
        encoding="utf-8",
    ) as f:
        tree = json.load(f)

    resolver = PermissionTreeResolver(tree)

    # ========================================================================
    # 1. Security groups
    # ========================================================================

    print("=" * 70)
    print("SECURITY GROUPS")
    print("=" * 70)

    print(
        json.dumps(
            resolver.security_groups(),
            indent=2,
        )
    )

    # ========================================================================
    # 2. Effective permissions for hr_manager
    # ========================================================================

    print("=" * 70)
    print("HR MANAGER - EFFECTIVE PERMISSIONS")
    print("=" * 70)

    result = resolver.effective_permissions(
        security_group="hr_manager",
        catalog="iceberg",
        schema="hr",
        table="employees",
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    # ========================================================================
    # 3. Effective actions for hr_manager
    # ========================================================================

    print("=" * 70)
    print("HR MANAGER - EFFECTIVE ACTIONS")
    print("=" * 70)

    result = resolver.effective_allowed_actions(
        security_group="hr_manager",
        catalog="iceberg",
        schema="hr",
        table="employees",
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    # ========================================================================
    # 4. Check SelectFromTableAction for hr_manager
    # ========================================================================

    print("=" * 70)
    print("HR MANAGER - SELECT ACTION")
    print("=" * 70)

    result = resolver.resolve_action(
        security_group="hr_manager",
        catalog="iceberg",
        schema="hr",
        table="employees",
        action="SelectFromTableAction",
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    # ========================================================================
    # 5. Check DropTableAction for hr_manager
    # ========================================================================

    print("=" * 70)
    print("HR MANAGER - DROP TABLE")
    print("=" * 70)

    result = resolver.resolve_action(
        security_group="hr_manager",
        catalog="iceberg",
        schema="hr",
        table="employees",
        action="DropTableAction",
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    # ========================================================================
    # 6. Check admin global access
    # ========================================================================

    print("=" * 70)
    print("ADMIN - DROP TABLE")
    print("=" * 70)

    result = resolver.resolve_action(
        security_group="admin",
        catalog="iceberg",
        schema="hr",
        table="employees",
        action="DropTableAction",
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    # ========================================================================
    # 7. Check analyst access
    # ========================================================================

    print("=" * 70)
    print("ANALYST - SELECT TABLE")
    print("=" * 70)

    result = resolver.resolve_action(
        security_group="analyst",
        catalog="iceberg",
        schema="hr",
        table="employees",
        action="SelectFromTableAction",
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    # ========================================================================
    # 8. Check analyst column mask
    # ========================================================================

    print("=" * 70)
    print("ANALYST - ATTRITION COLUMN MASK")
    print("=" * 70)

    result = resolver.get_column_mask(
        security_group="analyst",
        catalog="iceberg",
        schema="hr",
        table="employees",
        column="attrition",
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    # ========================================================================
    # 9. Check hr_manager column mask
    # ========================================================================

    print("=" * 70)
    print("HR MANAGER - ATTRITION COLUMN MASK")
    print("=" * 70)

    result = resolver.get_column_mask(
        security_group="hr_manager",
        catalog="iceberg",
        schema="hr",
        table="employees",
        column="attrition",
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    # ========================================================================
    # 10. Check business travel column mask
    # ========================================================================

    print("=" * 70)
    print("ANALYST - BUSINESS TRAVEL COLUMN MASK")
    print("=" * 70)

    result = resolver.get_column_mask(
        security_group="analyst",
        catalog="iceberg",
        schema="hr",
        table="employees",
        column="businesstravel",
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    # ========================================================================
    # 11. Collect all actions in tree
    # ========================================================================

    print("=" * 70)
    print("ALL ACTIONS")
    print("=" * 70)

    result = resolver.collect_allowed_actions()

    print(
        json.dumps(
            result,
            indent=2,
        )
    )