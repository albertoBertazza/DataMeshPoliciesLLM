
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ============================================================================
# Resource hierarchy
#
# 0 = ROOT
# 1 = catalog
# 2 = schema
# 3 = table / view / materialized view
# 4 = column
# ============================================================================

RESOURCE_DEPTH = {
    "root": 0,
    "catalog": 1,
    "schema": 2,
    "table": 3,
    "view": 3,
    "materialized_view": 3,
    "column": 4,
}


# ============================================================================
# Compiler
# ============================================================================

class PermissionCompiler:
    """
    Compile extracted authorization rules into canonical hierarchical
    data.json.

    Input:
        - extracted rules
        - data mesh
        - permission_depth.json

    Output:
        Canonical hierarchical authorization policy containing only
        local/direct declarations.

    Important:
        permission_depth.json is metadata about WHERE a permission
        can be materialized.

        It is NOT copied into the canonical policy.
    """

    def __init__(
        self,
        data_mesh: Dict[str, Any],
        permission_depth: Dict[str, int],
    ):
        self.data_mesh = data_mesh
        self.permission_depth = permission_depth

        self.errors: List[str] = []

        # Internal canonical representation:
        #
        # {
        #   resource_id: {
        #       "type": ...,
        #       "parent": ...,
        #       "rules": {
        #           group: {
        #               "allow": [],
        #               "deny": [],
        #               "row_filter": ...,
        #               "column_masks": ...
        #           }
        #       }
        #   }
        # }
        self.nodes: Dict[str, Dict[str, Any]] = {}

    # ========================================================================
    # Public API
    # ========================================================================

    def compile(
        self,
        extracted_rules: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        self.errors = []
        self.nodes = {}

        self._build_resource_tree()

        for index, rule in enumerate(extracted_rules):

            try:
                self._compile_rule(
                    rule,
                    rule_index=index,
                )

            except ValueError as exc:

                self.errors.append(
                    f"Rule {index}: {exc}"
                )

        if self.errors:

            raise ValueError(
                "Permission compilation failed:\n"
                + "\n".join(
                    f"- {error}"
                    for error in self.errors
                )
            )

        return self._build_output()

    # ========================================================================
    # Resource tree
    # ========================================================================

    def _build_resource_tree(self) -> None:

        self.nodes = {}

        # Root
        self.nodes["root"] = {
            "id": "root",
            "type": "root",
            "name": "ROOT",
            "parent": None,
            "rules": {},
        }

        # --------------------------------------------------------------------
        # Support the common Data Mesh structure:
        #
        # dataMeshStructure:
        #   catalogs:
        #     - catalogName:
        #       schemas:
        #         - schemaName:
        #           tables:
        #             - tableName:
        #               columns:
        # --------------------------------------------------------------------

        structure = self.data_mesh.get(
            "dataMeshStructure",
            self.data_mesh,
        )

        catalogs = structure.get(
            "catalogs",
            [],
        )

        for catalog in catalogs:

            catalog_name = catalog.get(
                "catalogName",
                "",
            )

            if not catalog_name:
                continue

            catalog_id = self._make_id(
                "catalog",
                catalog_name,
            )

            self._add_node(
                node_id=catalog_id,
                node_type="catalog",
                name=catalog_name,
                parent="root",
            )

            for schema in catalog.get(
                "schemas",
                [],
            ):

                schema_name = schema.get(
                    "schemaName",
                    "",
                )

                if not schema_name:
                    continue

                schema_id = self._make_id(
                    "schema",
                    catalog_name,
                    schema_name,
                )

                self._add_node(
                    node_id=schema_id,
                    node_type="schema",
                    name=schema_name,
                    parent=catalog_id,
                )

                for table in schema.get(
                    "tables",
                    [],
                ):

                    table_name = table.get(
                        "tableName",
                        "",
                    )

                    if not table_name:
                        continue

                    table_type = table.get(
                        "tableType",
                        "table",
                    )

                    if table_type not in (
                        "table",
                        "view",
                        "materialized_view",
                    ):
                        table_type = "table"

                    table_id = self._make_id(
                        table_type,
                        catalog_name,
                        schema_name,
                        table_name,
                    )

                    self._add_node(
                        node_id=table_id,
                        node_type=table_type,
                        name=table_name,
                        parent=schema_id,
                    )

                    for column in table.get(
                        "columns",
                        [],
                    ):

                        column_name = column.get(
                            "columnName",
                            "",
                        )

                        if not column_name:
                            continue

                        column_id = self._make_id(
                            "column",
                            catalog_name,
                            schema_name,
                            table_name,
                            column_name,
                        )

                        self._add_node(
                            node_id=column_id,
                            node_type="column",
                            name=column_name,
                            parent=table_id,
                        )

    # ========================================================================
    # Node helpers
    # ========================================================================

    @staticmethod
    def _make_id(
        resource_type: str,
        *parts: str,
    ) -> str:

        if resource_type == "root":
            return "root"

        return "/".join(
            [
                resource_type,
                *[
                    str(part)
                    for part in parts
                    if part != ""
                ],
            ]
        )

    def _add_node(
        self,
        node_id: str,
        node_type: str,
        name: str,
        parent: str,
    ) -> None:

        self.nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "name": name,
            "parent": parent,
            "rules": {},
        }

    # ========================================================================
    # Rule compilation
    # ========================================================================

    def _compile_rule(
        self,
        rule: Dict[str, Any],
        rule_index: int,
    ) -> None:

        subject_attribute = rule.get(
            "subject_attribute"
        )

        subject_value = rule.get(
            "subject_value"
        )

        resource_type = rule.get(
            "resource_type"
        )

        resource_values = rule.get(
            "resource_values",
            {}
        )

        permissions = rule.get(
            "permissions",
            {}
        )

        if subject_attribute not in (
            "user",
            "groups",
        ):
            raise ValueError(
                f"invalid subject_attribute "
                f"{subject_attribute!r}"
            )

        if not subject_value:
            raise ValueError(
                "subject_value is empty"
            )

        if resource_type not in (
            "catalog",
            "schema",
            "table",
            "column",
        ):
            raise ValueError(
                f"invalid resource_type "
                f"{resource_type!r}"
            )

        allow = permissions.get(
            "allow",
            [],
        )

        deny = permissions.get(
            "deny",
            [],
        )

        if not isinstance(allow, list):
            raise ValueError(
                "permissions.allow must be a list"
            )

        if not isinstance(deny, list):
            raise ValueError(
                "permissions.deny must be a list"
            )

        conflict = (
            set(allow) & set(deny)
        )

        if conflict:
            raise ValueError(
                "permission appears in both allow and deny: "
                + ", ".join(sorted(conflict))
            )

        target_node = self._resolve_resource(
            resource_type,
            resource_values,
        )

        if target_node is None:

            raise ValueError(
                "resource does not exist in Data Mesh: "
                + self._format_resource(
                    resource_type,
                    resource_values,
                )
            )

        # ------------------------------------------------------------
        # Compile ordinary permissions.
        # ------------------------------------------------------------

        for permission in allow:

            self._compile_permission(
                target_node=target_node,
                permission=permission,
                effect="allow",
                subject_attribute=subject_attribute,
                subject_value=subject_value,
            )

        for permission in deny:

            self._compile_permission(
                target_node=target_node,
                permission=permission,
                effect="deny",
                subject_attribute=subject_attribute,
                subject_value=subject_value,
            )

        # ------------------------------------------------------------
        # Row filter.
        # ------------------------------------------------------------

        if rule.get(
            "row_filter",
            False
        ):

            policy = rule.get(
                "row_filter_policy",
                {}
            )

            expression = policy.get(
                "expression",
                ""
            )

            if not expression:

                raise ValueError(
                    "row_filter=true but no row_filter_policy.expression "
                    "was supplied"
                )

            self._add_row_filter(
                target_node,
                subject_attribute,
                subject_value,
                expression,
            )

        # ------------------------------------------------------------
        # Column mask.
        # ------------------------------------------------------------

        if rule.get(
            "column_mask",
            False
        ):

            policy = rule.get(
                "column_mask_policy",
                {}
            )

            expression = policy.get(
                "expression",
                ""
            )

            if not expression:

                raise ValueError(
                    "column_mask=true but no "
                    "column_mask_policy.expression was supplied"
                )

            self._add_column_mask(
                target_node,
                subject_attribute,
                subject_value,
                resource_values.get(
                    "columnName",
                    "",
                ),
                expression,
            )

    # ========================================================================
    # Permission depth
    # ========================================================================

    def _compile_permission(
        self,
        target_node: Dict[str, Any],
        permission: str,
        effect: str,
        subject_attribute: str,
        subject_value: str,
    ) -> None:

        if permission not in self.permission_depth:

            raise ValueError(
                f"permission {permission!r} has no entry "
                f"in permission_depth.json"
            )

        permission_depth = self.permission_depth[
            permission
        ]

        target_depth = RESOURCE_DEPTH[
            target_node["type"]
        ]

        # ------------------------------------------------------------
        # A permission cannot be materialized above its defined depth.
        #
        # Example:
        #
        # SelectFromColumns = 4
        #
        # A table-level rule cannot materialize that permission at
        # the table itself. It must be resolved against the columns
        # belonging to that table.
        # ------------------------------------------------------------

        if permission_depth > target_depth:

            descendants = self._descendants_at_depth(
                target_node["id"],
                permission_depth,
            )

            if not descendants:

                raise ValueError(
                    f"permission {permission!r} requires depth "
                    f"{permission_depth}, but resource "
                    f"{target_node['id']!r} has no descendant "
                    f"resources at that depth"
                )

            for descendant in descendants:

                self._set_permission(
                    node=descendant,
                    permission=permission,
                    effect=effect,
                    subject_attribute=subject_attribute,
                    subject_value=subject_value,
                )

            return

        # ------------------------------------------------------------
        # Permission depth is the same as the target resource.
        # ------------------------------------------------------------

        if permission_depth == target_depth:

            self._set_permission(
                node=target_node,
                permission=permission,
                effect=effect,
                subject_attribute=subject_attribute,
                subject_value=subject_value,
            )

            return

        # ------------------------------------------------------------
        # Permission depth is above the requested resource.
        #
        # Do NOT automatically move the permission to an ancestor.
        #
        # That would broaden the authorization scope.
        #
        # Example:
        #
        # AccessCatalog = depth 1
        #
        # A rule specifically targeting one table must not silently
        # create:
        #
        # catalog/iceberg -> ALLOW AccessCatalog
        #
        # because that would affect every schema/table in iceberg.
        # ------------------------------------------------------------

        raise ValueError(
            f"permission {permission!r} is defined at depth "
            f"{permission_depth}, but the requested resource "
            f"{target_node['id']!r} has depth {target_depth}. "
            f"Moving the permission to an ancestor would broaden "
            f"the rule's scope."
        )

    # ========================================================================
    # Permission declaration
    # ========================================================================

    def _set_permission(
        self,
        node: Dict[str, Any],
        permission: str,
        effect: str,
        subject_attribute: str,
        subject_value: str,
    ) -> None:

        group_key = self._subject_key(
            subject_attribute,
            subject_value,
        )

        rules = node["rules"]

        if group_key not in rules:

            rules[group_key] = {
                "allow": [],
                "deny": [],
            }

        rule = rules[group_key]

        opposite = (
            "deny"
            if effect == "allow"
            else "allow"
        )

        if permission in rule[opposite]:

            raise ValueError(
                f"conflicting local declarations for "
                f"{permission!r} on {node['id']!r} "
                f"for {group_key!r}"
            )

        if permission not in rule[effect]:

            rule[effect].append(
                permission
            )

    # ========================================================================
    # Row filters
    # ========================================================================

    def _add_row_filter(
        self,
        node: Dict[str, Any],
        subject_attribute: str,
        subject_value: str,
        expression: str,
    ) -> None:

        group_key = self._subject_key(
            subject_attribute,
            subject_value,
        )

        if group_key not in node["rules"]:

            node["rules"][group_key] = {
                "allow": [],
                "deny": [],
            }

        rule = node["rules"][group_key]

        rule.setdefault(
            "row_filter",
            []
        )

        if expression not in rule["row_filter"]:

            rule["row_filter"].append(
                expression
            )

    # ========================================================================
    # Column masks
    # ========================================================================

    def _add_column_mask(
        self,
        node: Dict[str, Any],
        subject_attribute: str,
        subject_value: str,
        column_name: str,
        expression: str,
    ) -> None:

        if not column_name:

            raise ValueError(
                "column mask requires columnName"
            )

        group_key = self._subject_key(
            subject_attribute,
            subject_value,
        )

        if group_key not in node["rules"]:

            node["rules"][group_key] = {
                "allow": [],
                "deny": [],
            }

        rule = node["rules"][group_key]

        rule.setdefault(
            "column_masks",
            {}
        )

        if column_name in rule["column_masks"]:

            existing = rule[
                "column_masks"
            ][column_name]

            if existing != expression:

                raise ValueError(
                    f"multiple different column masks "
                    f"defined for {column_name!r} "
                    f"on {node['id']!r}"
                )

        rule[
            "column_masks"
        ][column_name] = expression

    # ========================================================================
    # Subject
    # ========================================================================

    @staticmethod
    def _subject_key(
        subject_attribute: str,
        subject_value: str,
    ) -> str:

        return subject_value

    # ========================================================================
    # Resource resolution
    # ========================================================================

    def _resolve_resource(
        self,
        resource_type: str,
        values: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        catalog = values.get(
            "catalogName",
            "",
        )

        schema = values.get(
            "schemaName",
            "",
        )

        table = values.get(
            "tableName",
            "",
        )

        column = values.get(
            "columnName",
            "",
        )

        if resource_type == "catalog":

            node_id = self._make_id(
                "catalog",
                catalog,
            )

        elif resource_type == "schema":

            node_id = self._make_id(
                "schema",
                catalog,
                schema,
            )

        elif resource_type == "table":

            node_id = self._make_id(
                "table",
                catalog,
                schema,
                table,
            )

            # The Data Mesh may explicitly distinguish views.
            if node_id not in self.nodes:

                node_id = self._make_id(
                    "view",
                    catalog,
                    schema,
                    table,
                )

            if node_id not in self.nodes:

                node_id = self._make_id(
                    "materialized_view",
                    catalog,
                    schema,
                    table,
                )

        elif resource_type == "column":

            node_id = self._make_id(
                "column",
                catalog,
                schema,
                table,
                column,
            )

        else:

            return None

        return self.nodes.get(
            node_id
        )

    # ========================================================================
    # Descendants
    # ========================================================================

    def _descendants_at_depth(
        self,
        node_id: str,
        depth: int,
    ) -> List[Dict[str, Any]]:

        result = []

        queue = [
            node_id
        ]

        while queue:

            current_id = queue.pop(0)

            current = self.nodes[
                current_id
            ]

            current_depth = RESOURCE_DEPTH[
                current["type"]
            ]

            if current_depth == depth:

                result.append(
                    current
                )

                continue

            for child in self.nodes.values():

                if child["parent"] == current_id:

                    queue.append(
                        child["id"]
                    )

        return result

    # ========================================================================
    # Output
    # ========================================================================

    def _build_output(
        self,
    ) -> Dict[str, Any]:

        resources = []

        for node in self.nodes.values():

            if node["type"] == "root":
                continue

            if not node["rules"]:
                continue

            resources.append(
                {
                    "id": node["id"],
                    "type": node["type"],
                    "parent": node["parent"],
                    "rules": self._clean_rules(
                        node["rules"]
                    ),
                }
            )

        return {
            "resources": resources
        }

    # ========================================================================
    # Remove empty rule properties
    # ========================================================================

    @staticmethod
    def _clean_rules(
        rules: Dict[str, Any],
    ) -> Dict[str, Any]:

        cleaned = {}

        for subject, rule in rules.items():

            value = {}

            if rule.get("allow"):

                value["allow"] = sorted(
                    set(rule["allow"])
                )

            if rule.get("deny"):

                value["deny"] = sorted(
                    set(rule["deny"])
                )

            if rule.get("row_filter"):

                value["row_filter"] = (
                    rule["row_filter"]
                )

            if rule.get("column_masks"):

                value["column_masks"] = (
                    rule["column_masks"]
                )

            if value:

                cleaned[subject] = value

        return cleaned

    # ========================================================================
    # Formatting
    # ========================================================================

    @staticmethod
    def _format_resource(
        resource_type: str,
        values: Dict[str, Any],
    ) -> str:

        parts = [
            values.get(
                "catalogName",
                "",
            ),
            values.get(
                "schemaName",
                "",
            ),
            values.get(
                "tableName",
                "",
            ),
            values.get(
                "columnName",
                "",
            ),
        ]

        parts = [
            part
            for part in parts
            if part
        ]

        return (
            f"{resource_type}: "
            + ".".join(parts)
        )


# ============================================================================
# File helpers
# ============================================================================

def load_json(
    path: str,
) -> Dict[str, Any]:

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:

        return json.load(file)


def load_permission_depth(
    path: str,
) -> Dict[str, int]:

    data = load_json(
        path
    )

    permission_depth = data.get(
        "permission_depth"
    )

    if not isinstance(
        permission_depth,
        dict
    ):

        raise ValueError(
            "permission_depth.json must contain "
            "a 'permission_depth' object"
        )

    result = {}

    for permission, depth in permission_depth.items():

        if not isinstance(
            depth,
            int
        ):

            raise ValueError(
                f"Invalid depth for permission "
                f"{permission!r}: {depth!r}"
            )

        if depth < 0 or depth > 4:

            raise ValueError(
                f"Invalid depth for permission "
                f"{permission!r}: {depth}"
            )

        result[permission] = depth

    return result


# ============================================================================
# Main convenience function
# ============================================================================

def compile_policy(
    extracted_rules: List[Dict[str, Any]],
    data_mesh_file: str,
    permission_depth_file: str,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:

    data_mesh = load_json(
        data_mesh_file
    )

    permission_depth = load_permission_depth(
        permission_depth_file
    )

    compiler = PermissionCompiler(
        data_mesh=data_mesh,
        permission_depth=permission_depth,
    )

    result = compiler.compile(
        extracted_rules
    )

    if output_file:

        output_path = Path(
            output_file
        )

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with open(
            output_path,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                result,
                file,
                indent=2,
                ensure_ascii=False,
            )

    return result
