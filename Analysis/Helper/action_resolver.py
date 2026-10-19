import json
from pathlib import Path
from typing import Any, Dict, List, Optional

class AuthorizationResolver:
    """
    Resolve authorization requests against a hierarchical
    permission policy.

    The resolver supports both:

        1. A single permission
           e.g. "SelectFromColumns"

        2. An action
           e.g. "SelectFromTableAction"

    For an action, the resolver:

        action
            ↓
        checkForAction.json
            ↓
        required permissions
            ↓
        resolve every permission
            ↓
        ALL permissions must be ALLOWED
            ↓
        final action decision

    Permission semantics:

        - explicit DENY anywhere in the hierarchy -> DENY
        - otherwise explicit ALLOW anywhere -> ALLOW
        - otherwise -> DEFAULT_DENY

    The hierarchy is evaluated from:

        target -> parent -> ... -> root

    Example:

        root/iceberg/hr/people

    is evaluated as:

        root/iceberg/hr/people
        root/iceberg/hr
        root/iceberg
        root
    """
    DEPTHS = { "root": 0, "catalog": 1, "schema": 2, "table": 3, "column": 4}

    # =========================================================
    # INIT
    # =========================================================

    def __init__( self, policy_file: str | Path, action_permissions_file: str | Path):
        self.policy_file = Path(policy_file)
        self.action_permissions_file = Path( action_permissions_file )
        self.policy = self._load_json( self.policy_file )
        self.action_permissions = self._load_json( self.action_permissions_file )
        self.rules = self.policy.get( "rules", {})

    # =========================================================
    # JSON
    # =========================================================

    @staticmethod
    def _load_json( path: Path) -> Any:
        with path.open( "r", encoding="utf-8") as f:
            return json.load(f)

    # =========================================================
    # RESOURCE
    # =========================================================

    @staticmethod
    def _resource_path( resource: Dict[str, Optional[str]]) -> str:
        parts = ["root"]
        for key in ( "catalog", "schema", "table", "column"):
            value = resource.get(key)
            if value:
                parts.append( str(value) )
        return "/".join(parts)

    @staticmethod
    def _resource_type( resource: Dict[str, Optional[str]]) -> str:
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
    def _ancestor_paths( resource_path: str) -> List[str]:
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
        return [ "/".join(parts[:i]) for i in range( len(parts), 0, -1) ]

    @classmethod
    def _depth_from_path( cls, path: str) -> int:
        return ( len(path.split("/")) - 1 )

    @staticmethod
    def _type_from_path( path: str) -> str:
        depth = ( len(path.split("/")) - 1 )
        return { 0: "root", 1: "catalog", 2: "schema", 3: "table", 4: "column"}.get( depth, "unknown")

    # =========================================================
    # PERMISSION RESOLUTION
    # =========================================================

    def _resolve_permission( self, resource_path: str, security_group: str, permission: str) -> Dict[str, Any]:
        """
        Resolve ONE permission.

        Semantics:

            if any explicit DENY exists:
                DENY

            elif any explicit ALLOW exists:
                ALLOW

            else:
                DEFAULT_DENY

        The hierarchy is scanned from target to root.

        All declarations are retained for provenance.
        """
        denied_at: List[ Dict[str, Any] ] = []
        allowed_at: List[ Dict[str, Any] ] = []
        declarations: List[ Dict[str, Any] ] = []
        # =====================================================
        # TARGET -> ROOT
        # =====================================================
        for path in self._ancestor_paths( resource_path ):
            path_rules = self.rules.get( path, {})
            group_rule = path_rules.get( security_group )
            if group_rule is None:
                continue
            permissions = group_rule.get( "permissions", {})
            allow = permissions.get( "allow", [])
            deny = permissions.get( "deny", [])
            if not isinstance( allow, list):
                allow = []
            if not isinstance( deny, list):
                deny = []
            # -------------------------------------------------
            # DECLARATION
            # -------------------------------------------------
            if ( permission in allow or permission in deny ):
                declaration = { "path": path, "type": self._type_from_path( path ), "depth": self._depth_from_path( path ), "allow": ( [permission] if permission in allow else [] ), "deny": ( [permission] if permission in deny else [] )}
                declarations.append( declaration )
            # -------------------------------------------------
            # DENY
            # -------------------------------------------------
            if permission in deny:
                denied_at.append( { "path": path, "type": self._type_from_path( path ), "depth": self._depth_from_path( path )} )
            # -------------------------------------------------
            # ALLOW
            # -------------------------------------------------
            if permission in allow:
                allowed_at.append( { "path": path, "type": self._type_from_path( path ), "depth": self._depth_from_path( path )} )
        # =====================================================
        # DENY
        # =====================================================
        if denied_at:
            return { "permission": permission, "allowed": False, "decision": "DENY", "deniedAt": denied_at, "allowedAt": allowed_at, "declarations": declarations}
        # =====================================================
        # ALLOW
        # =====================================================
        if allowed_at:
            return { "permission": permission, "allowed": True, "decision": "ALLOW", "deniedAt": [], "allowedAt": allowed_at, "declarations": declarations}
        # =====================================================
        # DEFAULT DENY
        # =====================================================
        return { "permission": permission, "allowed": False, "decision": "DEFAULT_DENY", "deniedAt": [], "allowedAt": [], "declarations": []}

    # =========================================================
    # OBLIGATIONS
    # =========================================================

    def resolve_obligations( self, resource_path: str, security_group: str) -> Dict[str, Any]:
        """
        Resolve row filters and column masks.

        Row filter:
            most-specific non-null value wins.

        Column masks:
            most-specific declaration wins per column.

        Obligations do not determine the action's
        authorization decision.
        """
        row_filter = None
        column_masks: Dict[ str, Any] = {}
        row_filter_found = False
        for path in self._ancestor_paths( resource_path ):
            path_rules = self.rules.get( path, {})
            group_rule = path_rules.get( security_group )
            if group_rule is None:
                continue

            # -------------------------------------------------
            # ROW FILTER
            # -------------------------------------------------
            if not row_filter_found:
                candidate = group_rule.get( "row_filter" )
                if candidate is not None:
                    row_filter = candidate
                    row_filter_found = True

            # -------------------------------------------------
            # COLUMN MASKS
            # -------------------------------------------------
            masks = group_rule.get( "column_masks", {})
            if not isinstance( masks, dict):
                continue
            for column, expression in masks.items():
                if column not in column_masks:
                    column_masks[column] = ( expression )
        return { "row_filter": row_filter, "column_masks": column_masks}

    # =========================================================
    # ACTION -> PERMISSIONS
    # =========================================================

    def _get_required_permissions( self, action: str) -> List[str]:
        """
        Return the permissions required by an action.

        Example:

            SelectFromTableAction

        might return:

            [
                "AccessCatalog",
                "ExecuteQuery",
                "GetColumnMask",
                "GetRowFilters",
                "SelectFromColumns"
            ]
        """
        permissions = self.action_permissions.get( action )
        if permissions is None:
            raise ValueError( f"Unknown action '{action}'. " "No action -> permission mapping exists." )
        if not isinstance( permissions, list):
            raise ValueError( f"Permission mapping for action " f"'{action}' must be a list." )
        return permissions

    # =========================================================
    # RESOLVE PERMISSION
    # =========================================================
    def resolve_permission( self, resource_path: str, security_group: str, permission: str) -> Dict[str, Any]:
        """
        Resolve a single permission.
        """
        details = self._resolve_permission( resource_path=resource_path, security_group=security_group, permission=permission)
        return details

    # =========================================================
    # RESOLVE ACTION
    # =========================================================
    def resolve_action( self, resource_path: str, security_group: str, action: str) -> Dict[str, Any]:
        """
        Resolve an action.

        The action is first expanded into its required
        permissions.

        Every required permission is resolved independently.

        Final action decision:

            ALL permissions allowed
                -> ALLOW

            otherwise
                -> DENY

        This means:

            required_permissions = [
                P1,
                P2,
                P3
            ]

            P1 = ALLOW
            P2 = ALLOW
            P3 = ALLOW

            => action ALLOW

        But:

            P1 = ALLOW
            P2 = DENY

            => action DENY
        """
        required_permissions = ( self._get_required_permissions( action ) )
        permission_results: Dict[ str, bool] = {}
        permission_details: Dict[ str, Dict[str, Any]] = {}

        # =====================================================
        # RESOLVE EVERY REQUIRED PERMISSION
        # =====================================================
        for permission in required_permissions:
            details = self._resolve_permission( resource_path=resource_path, security_group=security_group, permission=permission)
            permission_results[ permission ] = details["allowed"]
            permission_details[ permission ] = details

        # =====================================================
        # FINAL ACTION DECISION
        # =====================================================
        action_allowed = all( permission_results.values() )

        # -----------------------------------------------------
        # Determine why action was denied.
        # -----------------------------------------------------
        denied_permissions = [ permission for permission, allowed in permission_results.items() if not allowed ]
        if action_allowed:
            decision = "ALLOW"
        elif denied_permissions:
            decision = "DENY"
        else:
            decision = "DEFAULT_DENY"

        # =====================================================
        # OBLIGATIONS
        # =====================================================
        obligations = self.resolve_obligations( resource_path=resource_path, security_group=security_group)

        # =====================================================
        # RESULT
        # =====================================================
        return {
            "operation": action,
            "allowed": action_allowed,
            "decision": decision,
            "requiredPermissions": ( required_permissions ),
            "permissionResults": ( permission_results ),
            "permissionDetails": ( permission_details ),
            "deniedPermissions": ( denied_permissions ),
            "row_filter": ( obligations["row_filter"] ),
            "column_masks": ( obligations["column_masks"] ),
        }

    # =========================================================
    # PUBLIC RESOLVE
    # =========================================================

    def resolve( self, security_group: Any | None, action_or_permission: Any | None, resource: Dict[str, Optional[str]]) -> Dict[str, Any]:
        """
        Resolve either:

            - one permission
            - one action

        If the supplied operation exists in checkForAction.json,
        it is treated as an action.

        Otherwise it is treated as a permission.
        """

        # =====================================================
        # VALIDATE SECURITY GROUP
        # =====================================================
        if not security_group:
            return { "securityGroup": security_group, "resource": resource, "resourcePath": None, "resourceType": None, "operations": {}, "reason": "missing_security_group"}

        # =====================================================
        # VALIDATE OPERATION
        # =====================================================
        if not action_or_permission:
            return { "securityGroup": security_group, "resource": resource, "resourcePath": None, "resourceType": None, "operations": {}, "reason": "missing_operation"}

        # =====================================================
        # NORMALIZE RESOURCE
        # =====================================================
        if not isinstance( resource, dict):
            resource = {}
        normalized_resource = { "catalog": resource.get( "catalog" ), "schema": resource.get( "schema" ), "table": resource.get( "table" ), "column": resource.get( "column" )}

        # =====================================================
        # RESOURCE PATH
        # =====================================================
        resource_path = ( self._resource_path( normalized_resource ) )
        resource_type = ( self._resource_type( normalized_resource ) )

        # =====================================================
        # ACTION OR PERMISSION?
        # =====================================================
        if action_or_permission in ( self.action_permissions ):
            resolved = self.resolve_action( resource_path=resource_path, security_group=security_group, action=action_or_permission)
        else:
            resolved = self.resolve_permission( resource_path=resource_path, security_group=security_group, permission=action_or_permission)
        # =====================================================
        # FINAL RESULT
        # =====================================================
        return { "securityGroup": security_group, "resource": normalized_resource, "resourcePath": resource_path, "resourceType": resource_type, "operations": { action_or_permission: resolved }}
