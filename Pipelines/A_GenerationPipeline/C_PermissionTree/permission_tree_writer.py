import json
from pathlib import Path
from typing import Any, Dict

class PermissionTreeWriter:
    """
    Reads and writes the intermediate permission-tree structure.

    Two intermediate forms are supported:

    1. Extracted permission tree:
       {
           "subject_attribute": "groups",
           "subject_value": "hr_manager",
           "resource_type": "schema",
           "resource_values": {...},
           "column_masks": [...],
           "row_filters": [...]
       }

    2. Merged permission tree:
       {
           "resource_values": {
               ...
               "permissions": {
                   "hr_manager": {
                       "allow": [...],
                       "deny": [...],
                       "row_filter": ...,
                       "column_masks": {...}
                   }
               }
           }
       }

    This class only handles persistence and basic validation.
    It does NOT perform merging or permission resolution.
    """

    @staticmethod
    def write( tree: Dict[str, Any], output_file: str ) -> None:
        if not isinstance(tree, dict):
            raise ValueError( "Permission tree must be a JSON object" )
        path = Path(output_file)
        path.parent.mkdir( parents=True, exist_ok=True )
        with open( path, "w", encoding="utf-8" ) as file:
            json.dump( tree, file, indent=2, ensure_ascii=False )
            file.write("\n")

    @staticmethod
    def load( input_file: str ) -> Dict[str, Any]:
        path = Path(input_file)
        if not path.exists():
            raise FileNotFoundError( f"Permission tree file does not exist: " f"{input_file}" )
        with open( path, "r", encoding="utf-8" ) as file:
            data = json.load(file)
        if not isinstance(data, dict):
            raise ValueError( "Permission tree must be a JSON object" )
        PermissionTreeWriter._validate(data)
        return data

    # ========================================================================
    # Validation
    # ========================================================================

    @staticmethod
    def _validate(tree: Dict[str, Any]) -> None:
        if "resource_values" not in tree:
            raise ValueError( "Permission tree must contain " "'resource_values'" )
        resource_values = tree["resource_values"]
        if not isinstance(resource_values, dict):
            raise ValueError( "'resource_values' must be an object" )

        # ------------------------------------------------------------
        # Extracted tree
        #
        # The extraction step has one security group.
        # ------------------------------------------------------------
        if "subject_value" in tree:
            if not tree.get("subject_attribute"):
                raise ValueError( "Extracted permission tree is missing " "'subject_attribute'" )
            if not isinstance( tree["subject_value"], str ) or not tree["subject_value"]:
                raise ValueError( "Extracted permission tree has an invalid " "'subject_value'" )

        # ------------------------------------------------------------
        # Merged tree
        #
        # No subject_value is required because the group is stored
        # at each resource:
        #
        # permissions:
        #   hr_manager:
        #     allow: ...
        #     deny: ...
        # ------------------------------------------------------------

        PermissionTreeWriter._validate_resource_values( resource_values )

    # ========================================================================
    # Resource validation
    # ========================================================================

    @staticmethod
    def _validate_resource_values( resource_values: Dict[str, Any] ) -> None:
        # Root
        root = resource_values.get("root")
        if root is not None:
            PermissionTreeWriter._validate_resource( root )
        # Catalogs
        catalogs = resource_values.get( "catalogs", [] )
        if not isinstance(catalogs, list):
            raise ValueError( "'resource_values.catalogs' must be a list" )
        for catalog in catalogs:
            if not isinstance(catalog, dict):
                raise ValueError( "Each catalog must be an object" )
            PermissionTreeWriter._validate_resource( catalog )
            schemas = catalog.get( "schemas", [] )
            if not isinstance(schemas, list):
                raise ValueError( "Catalog 'schemas' must be a list" )
            for schema in schemas:
                if not isinstance(schema, dict):
                    raise ValueError( "Each schema must be an object" )
                PermissionTreeWriter._validate_resource( schema )
                tables = schema.get( "tables", [] )
                if not isinstance(tables, list):
                    raise ValueError( "Schema 'tables' must be a list" )
                for table in tables:
                    if not isinstance(table, dict):
                        raise ValueError( "Each table must be an object" )
                    PermissionTreeWriter._validate_resource( table )
                    columns = table.get( "columns", [] )
                    if not isinstance(columns, list):
                        raise ValueError( "Table 'columns' must be a list" )
                    for column in columns:
                        if isinstance(column, str):
                            continue
                        if not isinstance(column, dict):
                            raise ValueError( "Each column must be an object " "or string" )
                        PermissionTreeWriter._validate_resource( column )

    # ========================================================================
    # Single resource
    # ========================================================================

    @staticmethod
    def _validate_resource( resource: Dict[str, Any] ) -> None:
        if not isinstance(resource, dict):
            raise ValueError( "Resource must be an object" )
        permissions = resource.get( "permissions" )
        if permissions is None:
            return
        if not isinstance(permissions, dict):
            raise ValueError( "Resource 'permissions' must be an object" )

        # ------------------------------------------------------------
        # Old extracted/local representation:
        #
        # "permissions": {
        #     "allow": [...],
        #     "deny": [...]
        # }
        #
        # This is valid for an extracted tree.
        # ------------------------------------------------------------
        if ( "allow" in permissions or "deny" in permissions ):
            PermissionTreeWriter._validate_permission_rule( permissions )
            return

        # ------------------------------------------------------------
        # New merged representation:
        #
        # "permissions": {
        #     "hr_manager": {
        #         "allow": [...],
        #         "deny": [...],
        #         "row_filter": null,
        #         "column_masks": {}
        #     }
        # }
        # ------------------------------------------------------------
        for group, rule in permissions.items():
            if not isinstance(group, str) or not group:
                raise ValueError( "Permission group name must be a " "non-empty string" )
            PermissionTreeWriter._validate_permission_rule( rule )

    # ========================================================================
    # Permission rule
    # ========================================================================

    @staticmethod
    def _validate_permission_rule( rule: Dict[str, Any] ) -> None:
        if not isinstance(rule, dict):
            raise ValueError( "Permission rule must be an object" )
        allow = rule.get( "allow", [] )
        deny = rule.get( "deny", [] )
        if not isinstance(allow, list):
            raise ValueError( "'allow' must be a list" )
        if not isinstance(deny, list):
            raise ValueError( "'deny' must be a list" )
        if set(allow) & set(deny):
            raise ValueError( "The same permission cannot appear " "in both 'allow' and 'deny'" )
        row_filter = rule.get( "row_filter" )
        if ( row_filter is not None and not isinstance(row_filter, str) ):
            raise ValueError( "'row_filter' must be a string or null" )
        column_masks = rule.get( "column_masks", {} )
        if not isinstance(column_masks, dict):
            raise ValueError( "'column_masks' must be an object" )
