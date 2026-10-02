import json
from pathlib import Path
from typing import Any, Dict, List

from Pipelines.B_TestAndEvaluationPipeline.A_TestGeneration.Resolver.draw_tree import ( print_permission_tree )

class AuthorizationResolver:
    """
    Resolve rewritten authorization rules against the hierarchical
    permission policy.

    Semantics
    ---------
    1. The explicit resource from the rewritten rule defines the
       authorization/test depth.

    2. Normal permissions use most-specific explicit declaration:
           target -> parent -> ... -> root

       The first explicit ALLOW or DENY found wins.

       If no declaration exists:
           DEFAULT DENY

    3. GetColumnMask and GetRowFilters are obligation permissions.
       They are authorized independently and their actual values
       are resolved separately.

    4. Row filters:
           Most-specific non-null declaration on the target -> root
           chain wins.

    5. Column masks:
           Masks may be declared on the target, an ancestor,
           or on descendant column resources.

           For each column, the most-specific declaration wins.

    6. Metadata visibility filters are NOT normal permissions.

       Their actual declarations are stored separately, for example:

           "root/iceberg": {
               "auditor": {...},
               "FilterSchemas": {
                   "auditor": ["hr"]
               }
           }

       resolve_filters() returns those actual declarations.

    7. An action is allowed only when every required normal
       permission is allowed.
    """

    # Keep deterministic order.
    FILTER_PERMISSIONS = ( "FilterCatalogs", "FilterSchemas", "FilterTables", "FilterColumns")

    OBLIGATION_PERMISSIONS = { "GetColumnMask", "GetRowFilters"}

    DEPTHS = { "root": 0, "catalog": 1, "schema": 2, "table": 3, "column": 4}

    def __init__( self, rewrite_file: str | Path, policy_file: str | Path, action_permissions_file: str | Path ):
        self.rewrite_file = Path(rewrite_file)
        self.policy_file = Path(policy_file)
        self.action_permissions_file = Path(action_permissions_file)

        self.rewrites = self._load_json(self.rewrite_file)
        self.policy = self._load_json(self.policy_file)
        self.action_permissions = self._load_json( self.action_permissions_file )

        self.rules = self.policy.get("rules", {})

        if not isinstance(self.rules, dict):
            self.rules = {}

    # =========================================================
    # JSON
    # =========================================================

    @staticmethod
    def _load_json(path: Path) -> Any:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

    # =========================================================
    # RESOURCE
    # =========================================================

    @staticmethod
    def _resource_path(resource: Dict[str, str]) -> str:
        """
        Convert:

            {
                "catalog": "iceberg",
                "schema": "hr",
                "table": "people",
                "column": ""
            }

        into:

            root/iceberg/hr/people
        """

        parts = ["root"]

        for key in ( "catalog", "schema", "table", "column" ):
            value = resource.get(key, "")

            if value:
                parts.append(value)

        return "/".join(parts)

    @staticmethod
    def _resource_type(resource: Dict[str, str]) -> str:

        if resource.get("column"):
            return "column"

        if resource.get("table"):
            return "table"

        if resource.get("schema"):
            return "schema"

        if resource.get("catalog"):
            return "catalog"

        return "root"

    # =========================================================
    # HIERARCHY
    # =========================================================

    @staticmethod
    def _ancestor_paths(resource_path: str) -> List[str]:
        """
        Return paths from most-specific to root.

        Example:

            root/iceberg/hr/people

        becomes:

            [
                root/iceberg/hr/people,
                root/iceberg/hr,
                root/iceberg,
                root
            ]
        """

        parts = resource_path.split("/")

        return [ "/".join(parts[:i]) for i in range(len(parts), 0, -1) ]

    @classmethod
    def _depth_from_path(cls, path: str) -> int:
        parts = path.split("/")
        return len(parts) - 1

    @staticmethod
    def _type_from_path(path: str) -> str:

        depth = len(path.split("/")) - 1

        return { 0: "root", 1: "catalog", 2: "schema", 3: "table", 4: "column"}.get(depth, "unknown")

    # =========================================================
    # PERMISSION DETAILS
    # =========================================================

    def _permission_details( self, resource_path: str, security_group: str, permission: str ) -> Dict[str, Any]:
        """
        Resolve one normal permission.

        Semantics:

            target explicit declaration wins

            otherwise parent explicit declaration wins

            otherwise ...

            otherwise DEFAULT_DENY

        Therefore:

            root       -> DENY
            catalog    -> ALLOW

        for a catalog-targeted request results in ALLOW because
        the catalog declaration is more specific.
        """

        # -----------------------------------------------------
        # Obligation permissions
        # -----------------------------------------------------

        if permission in self.OBLIGATION_PERMISSIONS:

            return { "allowed": True, "decision": "ALLOW", "deniedAt": [], "allowedAt": [], "declarations": []}

        # -----------------------------------------------------
        # Walk target -> root
        # -----------------------------------------------------

        for path in self._ancestor_paths(resource_path):

            path_rules = self.rules.get(path, {})

            if not isinstance(path_rules, dict):
                continue

            group_rule = path_rules.get(security_group)

            if not isinstance(group_rule, dict):
                continue

            permissions = group_rule.get( "permissions", {} )

            if not isinstance(permissions, dict):
                continue

            allow = permissions.get("allow", [])
            deny = permissions.get("deny", [])

            if not isinstance(allow, list):
                allow = []

            if not isinstance(deny, list):
                deny = []

            # -------------------------------------------------
            # First explicit declaration wins.
            # -------------------------------------------------

            if permission in allow or permission in deny:

                declaration = { "path": path, "type": self._type_from_path(path), "depth": self._depth_from_path(path), "allow": ( [permission] if permission in allow else [] ), "deny": ( [permission] if permission in deny else [] )}

                # Conflict should normally already have been
                # prevented by compilation. If it happens,
                # resolve conservatively as DENY.
                if permission in allow and permission in deny:

                    return { "allowed": False, "decision": "DENY_CONFLICT", "deniedAt": [declaration], "allowedAt": [declaration], "declarations": [declaration]}

                # Explicit DENY at nearest declaration.
                if permission in deny:

                    return { "allowed": False, "decision": "DENY", "deniedAt": [{ "path": path, "type": self._type_from_path(path), "depth": self._depth_from_path(path)}], "allowedAt": [], "declarations": [declaration]}

                # Explicit ALLOW at nearest declaration.
                return { "allowed": True, "decision": "ALLOW", "deniedAt": [], "allowedAt": [{ "path": path, "type": self._type_from_path(path), "depth": self._depth_from_path(path)}], "declarations": [declaration]}

        # -----------------------------------------------------
        # No declaration anywhere -> DEFAULT DENY
        # -----------------------------------------------------

        return { "allowed": False, "decision": "DEFAULT_DENY", "deniedAt": [], "allowedAt": [], "declarations": []}

    # =========================================================
    # METADATA FILTER DECLARATIONS
    # =========================================================

    @staticmethod
    def _empty_filters() -> Dict[str, Dict[str, List[str]]]:

        return { "FilterCatalogs": { "allowed": [], "deny": []}, "FilterSchemas": { "allowed": [], "deny": []}, "FilterTables": { "allowed": [], "deny": []}, "FilterColumns": { "allowed": [], "deny": []}}

    def resolve_filters( self, resource_path: str, security_group: str) -> Dict[str, Any]:
        """
        Resolve actual metadata visibility declarations.

        IMPORTANT:

        Normal permission:

            group_rule["permissions"]["allow"]

        is different from:

            path_rules["FilterSchemas"][security_group]

        Example canonical policy:

            "root/iceberg": {
                "auditor": {
                    "permissions": {
                        "allow": [
                            "FilterSchemas"
                        ]
                    }
                },
                "FilterSchemas": {
                    "auditor": ["hr"]
                }
            }

        The first says the group has permission to perform
        schema filtering.

        The second says which schema must actually be filtered.

        Resolution:
            most-specific explicit filter declaration wins.

        Because compiler output currently represents a filter list
        as a denied-object list:

            "FilterSchemas": {
                "auditor": ["hr"]
            }

        it becomes:

            {
                "allowed": [],
                "deny": ["hr"]
            }

        A dict form is also supported:

            "FilterSchemas": {
                "auditor": {
                    "allowed": [],
                    "deny": ["hr"]
                }
            }
        """

        result = self._empty_filters()

        # IMPORTANT:
        # An empty declaration is still an explicit declaration.
        #
        # Therefore this cannot be inferred by checking whether
        # result["..."] is still empty.
        resolved = { filter_name: False for filter_name in self.FILTER_PERMISSIONS }

        # -----------------------------------------------------
        # Target -> root
        # -----------------------------------------------------

        for path in self._ancestor_paths(resource_path):

            path_rules = self.rules.get(path, {})

            if not isinstance(path_rules, dict):
                continue

            for filter_name in self.FILTER_PERMISSIONS:

                if resolved[filter_name]:
                    continue

                declaration = path_rules.get(filter_name)

                if declaration is None:
                    continue

                # -------------------------------------------------
                # Current canonical representation:
                #
                # "FilterSchemas": {
                #     "auditor": ["hr"]
                # }
                # -------------------------------------------------

                if isinstance(declaration, dict):

                    value = declaration.get( security_group )

                    if value is None:
                        continue

                    if isinstance(value, list):

                        result[filter_name] = { "allowed": [], "deny": list(value)}

                        resolved[filter_name] = True
                        continue

                    # -------------------------------------------------
                    # Also support:
                    #
                    # "FilterSchemas": {
                    #     "auditor": {
                    #         "allowed": [],
                    #         "deny": ["hr"]
                    #     }
                    # }
                    # -------------------------------------------------

                    if isinstance(value, dict):

                        allowed = value.get( "allowed", [] )

                        deny = value.get( "deny", [] )

                        if not isinstance( allowed, list ):
                            allowed = []

                        if not isinstance( deny, list ):
                            deny = []

                        result[filter_name] = { "allowed": list(allowed), "deny": list(deny)}

                        resolved[filter_name] = True

        return result

    # =========================================================
    # NORMAL PERMISSIONS
    # =========================================================

    def resolve_permission( self, resource_path: str, security_group: str, permission: str ) -> bool:
        """
        Backward-compatible boolean permission resolution.
        """

        details = self._permission_details( resource_path=resource_path, security_group=security_group, permission=permission)

        return details["allowed"]

    # =========================================================
    # OBLIGATIONS
    # =========================================================

    def resolve_obligations( self, resource_path: str, security_group: str) -> Dict[str, Any]:
        """
        Resolve row filters and column masks.

        Row filters:
            Most-specific non-null declaration on the target
            -> root chain wins.

        Column masks:
            A mask may be declared on:
                - target
                - ancestor
                - descendant column resource

            For each column, the most-specific declaration wins.
        """

        row_filter = None
        row_filter_found = False

        # column -> {
        #     depth: int,
        #     expression: str
        # }
        mask_candidates: Dict[str, Dict[str, Any]] = {}

        ancestor_paths = self._ancestor_paths( resource_path )

        # =====================================================
        # 1. Target + ancestors
        # =====================================================

        for path in ancestor_paths:

            path_rules = self.rules.get(path, {})

            if not isinstance(path_rules, dict):
                continue

            group_rule = path_rules.get( security_group )

            if not isinstance(group_rule, dict):
                continue

            # -------------------------------------------------
            # Row filter
            # -------------------------------------------------

            if not row_filter_found:

                candidate = group_rule.get( "row_filter" )

                if ( isinstance(candidate, str) and candidate.strip() ):

                    row_filter = candidate.strip()
                    row_filter_found = True

            # -------------------------------------------------
            # Masks directly on target / ancestors
            # -------------------------------------------------

            masks = group_rule.get( "column_masks", {} )

            if not isinstance(masks, dict):
                continue

            current_depth = self._depth_from_path( path )

            for column, expression in masks.items():

                if not isinstance(column, str):
                    continue

                if not isinstance(expression, str):
                    continue

                column = column.strip()
                expression = expression.strip()

                if not column or not expression:
                    continue

                previous = mask_candidates.get( column )

                if ( previous is None or current_depth > previous["depth"] ):

                    mask_candidates[column] = { "depth": current_depth, "expression": expression}

        # =====================================================
        # 2. Descendant column masks
        #
        # Example:
        #
        # request:
        #   root/iceberg/finance/employee_finance
        #
        # mask:
        #   root/iceberg/finance/employee_finance/employee_id
        #
        # The table request must still receive the mask.
        # =====================================================

        prefix = resource_path + "/"

        for path, path_rules in self.rules.items():

            if not isinstance(path, str):
                continue

            if not path.startswith(prefix):
                continue

            if self._depth_from_path(path) != 4:
                continue

            if not isinstance(path_rules, dict):
                continue

            group_rule = path_rules.get( security_group )

            if not isinstance(group_rule, dict):
                continue

            masks = group_rule.get( "column_masks", {} )

            if not isinstance(masks, dict):
                continue

            column_depth = self._depth_from_path( path )

            for column, expression in masks.items():

                if not isinstance(column, str):
                    continue

                if not isinstance(expression, str):
                    continue

                column = column.strip()
                expression = expression.strip()

                if not column or not expression:
                    continue

                previous = mask_candidates.get( column )

                if ( previous is None or column_depth > previous["depth"] ):

                    mask_candidates[column] = { "depth": column_depth, "expression": expression}

        # =====================================================
        # 3. Final masks
        # =====================================================

        column_masks = { column: value["expression"] for column, value in mask_candidates.items() }

        return { "row_filter": row_filter, "column_masks": column_masks}

    # =========================================================
    # ACTION
    # =========================================================

    def resolve_action( self, resource_path: str, security_group: str, action: str ) -> Dict[str, Any]:
        """
        Resolve one action against the explicit resource target.
        """

        required_permissions = ( self.action_permissions.get(action) )

        # -----------------------------------------------------
        # Unknown action
        # -----------------------------------------------------

        if required_permissions is None:

            return { "action": action, "allowed": False, "reason": "unknown_action", "requiredPermissions": [], "permissionResults": {}, "permissionDetails": {}, "row_filter": None, "column_masks": {}}

        # -----------------------------------------------------
        # Remove duplicate permissions
        # -----------------------------------------------------

        required_permissions = list( dict.fromkeys(required_permissions) )

        permission_results: Dict[str, bool] = {}
        permission_details: Dict[str, Dict[str, Any]] = {}

        # -----------------------------------------------------
        # Resolve required permissions
        # -----------------------------------------------------

        for permission in required_permissions:

            details = self._permission_details( resource_path=resource_path, security_group=security_group, permission=permission)

            permission_results[permission] = ( details["allowed"] )

            permission_details[permission] = details

        # -----------------------------------------------------
        # Resolve obligations
        # -----------------------------------------------------

        obligations = self.resolve_obligations( resource_path=resource_path, security_group=security_group)

        # -----------------------------------------------------
        # Resolve actual metadata filter declarations too.
        #
        # This is useful for the resolver output / graph.
        # -----------------------------------------------------

        filters = self.resolve_filters( resource_path=resource_path, security_group=security_group)

        # -----------------------------------------------------
        # Action decision
        # -----------------------------------------------------

        allowed = all( permission_results.values() )

        return {
            "action": action,
            "allowed": allowed,
            "requiredPermissions": required_permissions,
            "permissionResults": permission_results,
            "permissionDetails": permission_details,
            "row_filter": obligations["row_filter"],
            "column_masks": obligations["column_masks"],
            "filters": filters,
        }

    # =========================================================
    # REWRITE
    # =========================================================

    def resolve_rewrite( self, rewrite: Dict[str, Any] ) -> List[Dict[str, Any]]:
        """
        Resolve one rewritten authorization object.

        The explicit resource determines the authorization/test
        depth.

        expandedResources is NOT used to create separate resolver
        authorization targets.
        """

        security_group = rewrite.get( "securityGroup" )

        # -----------------------------------------------------
        # Invalid / unknown security group
        # -----------------------------------------------------

        if not rewrite.get( "existSecureGroup", False ):
            return []

        # -----------------------------------------------------
        # Invalid action information
        #
        # An empty action list is valid for filter-only rules,
        # row-filter-only rules, or mask-only rules.
        #
        # Therefore actionExist=true with actions=[] is accepted.
        # -----------------------------------------------------

        if not rewrite.get( "actionExist", False ):
            return []

        # -----------------------------------------------------
        # Original explicit resource
        # -----------------------------------------------------

        rule_resource = rewrite.get( "resource", {} )

        if not isinstance( rule_resource, dict ):
            return []

        resource = { "catalog": rule_resource.get( "catalog", "" ), "schema": rule_resource.get( "schema", "" ), "table": rule_resource.get( "table", "" ), "column": rule_resource.get( "column", "" )}

        resource_path = self._resource_path( resource )

        resource_type = self._resource_type( resource )

        actions: Dict[str, Any] = {}

        # =====================================================
        # INTENDED ALLOW
        # =====================================================

        for action in rewrite.get( "allowed", [] ):

            resolved = self.resolve_action( resource_path=resource_path, security_group=security_group, action=action)

            resolved["expectedDecision"] = "ALLOW"
            resolved["expectedAllowed"] = True
            resolved["expectationMatches"] = ( resolved["allowed"] is True )

            actions[action] = resolved

        # =====================================================
        # INTENDED DENY
        # =====================================================

        for action in rewrite.get( "deny", [] ):

            required_permissions = ( self.action_permissions.get( action, [] ) )

            required_permissions = list( dict.fromkeys( required_permissions ) )

            permission_results: Dict[ str, bool ] = {}

            permission_details: Dict[ str, Dict[str, Any] ] = {}

            for permission in required_permissions:

                details = self._permission_details( resource_path=resource_path, security_group=security_group, permission=permission)

                permission_results[ permission ] = details["allowed"]

                permission_details[ permission ] = details

            obligations = self.resolve_obligations( resource_path=resource_path, security_group=security_group)

            filters = self.resolve_filters( resource_path=resource_path, security_group=security_group)

            actions[action] = {
                "action": action,
                "allowed": False,
                "expectedDecision": "DENY",
                "expectedAllowed": False,
                "expectationMatches": True,
                "requiredPermissions": required_permissions,
                "permissionResults": permission_results,
                "permissionDetails": permission_details,
                "row_filter": obligations["row_filter"],
                "column_masks": obligations["column_masks"],
                "filters": filters,
                "reason": "explicit_rewrite_deny",
            }

        # =====================================================
        # Resolve actual obligations/filter declarations even
        # when the rule has NO ordinary action.
        #
        # This is required for:
        #
        #   FilterSchemas
        #   FilterCatalogs
        #   FilterTables
        #   FilterColumns
        #   row filters
        #   column masks
        # =====================================================

        obligations = self.resolve_obligations( resource_path=resource_path, security_group=security_group)

        filters = self.resolve_filters( resource_path=resource_path, security_group=security_group)

        # =====================================================
        # ONE RESULT FOR THE EXPLICIT RULE RESOURCE
        # =====================================================

        return [
            {
                "securityGroup": security_group,
                "resource": resource,
                "resourcePath": resource_path,
                "resourceType": resource_type,
                "actions": actions,

                # Actual resolved obligations
                "row_filter": obligations[ "row_filter" ],
                "column_masks": obligations[ "column_masks" ],

                # Actual metadata visibility declarations
                "filters": filters,
            }
        ]

    # =========================================================
    # RESOLVE EVERYTHING
    # =========================================================

    def resolve(self) -> List[Dict[str, Any]]:
        """
        Resolve every rewritten authorization object.
        """

        results: List[ Dict[str, Any] ] = []

        # -----------------------------------------------------
        # Rewrite file formats
        # -----------------------------------------------------

        if isinstance( self.rewrites, list ):

            rewrites = self.rewrites

        elif isinstance( self.rewrites, dict ):

            if "securityGroup" in self.rewrites:

                rewrites = [ self.rewrites ]

            else:

                rewrites = self.rewrites.get( "rules", [] )

        else:

            rewrites = []

        # -----------------------------------------------------
        # Resolve
        # -----------------------------------------------------

        for rewrite in rewrites:

            if not isinstance( rewrite, dict ):
                continue

            results.extend( self.resolve_rewrite( rewrite ) )

        print("=" * 60)
        print("RESOLVER OUTPUT")
        print("=" * 60)

        print( json.dumps( results, indent=2, ensure_ascii=False ) )

        print_permission_tree( results )

        return results

    # =========================================================
    # SAVE
    # =========================================================

    def save( self, output_file: str | Path ) -> List[Dict[str, Any]]:

        results = self.resolve()

        output_file = Path( output_file )

        output_file.parent.mkdir( parents=True, exist_ok=True )

        with output_file.open( "w", encoding="utf-8" ) as f:

            json.dump( results, f, indent=2, ensure_ascii=False )

        return results
