import json
from pathlib import Path
from typing import Any, Dict, List

class AuthorizationResolver:
    """
    Resolve rewritten authorization rules against the hierarchical
    permission policy.

    Semantics
    ---------
    1. Concrete resources come from expandedResources.
    2. Actions are translated into required permissions using the
       action-permission mapping.
    3. Normal permissions:
           ALLOW -> True
           DENY  -> False
           none  -> False
    4. A DENY anywhere in the resource hierarchy has priority over
       an ALLOW.
    5. GetColumnMask and GetRowFilters are obligation permissions.
       They are always authorized and their actual values are resolved
       separately.
    6. An action is allowed only when every required permission is
       allowed.
    7. permissionDetails records where every permission was declared
       and where the final decision came from.
    """

    OBLIGATION_PERMISSIONS = { "GetColumnMask", "GetRowFilters"}

    DEPTHS = { "root": 0, "catalog": 1, "schema": 2, "table": 3, "column": 4}

    def __init__( self, rewrite_file: str | Path, policy_file: str | Path, action_permissions_file: str | Path):
        self.rewrite_file = Path(rewrite_file)
        self.policy_file = Path(policy_file)
        self.action_permissions_file = Path( action_permissions_file )

        self.rewrites = self._load_json( self.rewrite_file )
        self.policy = self._load_json( self.policy_file )
        self.action_permissions = self._load_json( self.action_permissions_file )

        self.rules = self.policy.get( "rules", {})

    # =========================================================
    # JSON
    # =========================================================

    @staticmethod
    def _load_json(path: Path) -> Any:
        with path.open( "r", encoding="utf-8") as f:
            return json.load(f)

    # =========================================================
    # RESOURCE
    # =========================================================

    @staticmethod
    def _resource_path( resource: Dict[str, str]) -> str:
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
        for key in ( "catalog", "schema", "table", "column"):
            value = resource.get( key, "")
            if value:
                parts.append(value)
        return "/".join(parts)

    @staticmethod
    def _resource_type( resource: Dict[str, str]) -> str:
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
        parts = path.split("/")
        # root
        # root/catalog
        # root/catalog/schema
        # ...
        return len(parts) - 1

    @staticmethod
    def _type_from_path( path: str) -> str:
        depth = len(path.split("/")) - 1
        return { 0: "root", 1: "catalog", 2: "schema", 3: "table", 4: "column"}.get( depth, "unknown")

    # =========================================================
    # PERMISSION DETAILS
    # =========================================================

    def _permission_details( self, resource_path: str, security_group: str, permission: str) -> Dict[str, Any]:
        """
        Resolve one permission and return both the boolean result
        and provenance information.

        DENY semantics:
            Any explicit DENY anywhere in the hierarchy wins.

        ALLOW semantics:
            If there is no DENY but at least one ALLOW exists,
            the permission is ALLOW.

        Undefined:
            If no ALLOW and no DENY exist,
            the permission is DENY.
        """

        # -----------------------------------------------------
        # Obligation permissions
        # -----------------------------------------------------
        if permission in self.OBLIGATION_PERMISSIONS:
            return { "allowed": True, "decision": "ALLOW", "deniedAt": [], "allowedAt": [], "declarations": []}
        denied_at: List[Dict[str, Any]] = []
        allowed_at: List[Dict[str, Any]] = []
        declarations: List[Dict[str, Any]] = []

        # -----------------------------------------------------
        # Walk target -> root
        # -----------------------------------------------------
        for path in self._ancestor_paths( resource_path ):
            path_rules = self.rules.get( path, {})
            group_rule = path_rules.get( security_group )
            if group_rule is None:
                continue
            permissions = group_rule.get( "permissions", {})
            allow = permissions.get( "allow", [])
            deny = permissions.get( "deny", [])

            # -------------------------------------------------
            # Record declarations for this permission.
            # -------------------------------------------------
            if ( permission in allow or permission in deny ):
                declaration = { "path": path, "type": self._type_from_path( path ), "depth": self._depth_from_path( path ), "allow": ( [permission] if permission in allow else [] ), "deny": ( [permission] if permission in deny else [] )}
                declarations.append( declaration )

            # -------------------------------------------------
            # Explicit DENY
            # -------------------------------------------------
            if permission in deny:
                denied_at.append( { "path": path, "type": self._type_from_path( path ), "depth": self._depth_from_path( path )} )

            # -------------------------------------------------
            # Explicit ALLOW
            # -------------------------------------------------
            if permission in allow:
                allowed_at.append( { "path": path, "type": self._type_from_path( path ), "depth": self._depth_from_path( path )} )

        # -----------------------------------------------------
        # DENY wins everywhere
        # -----------------------------------------------------
        if denied_at:
            return { "allowed": False, "decision": "DENY", "deniedAt": denied_at, "allowedAt": allowed_at, "declarations": declarations}

        # -----------------------------------------------------
        # ALLOW if at least one explicit ALLOW exists
        # -----------------------------------------------------
        if allowed_at:
            return { "allowed": True, "decision": "ALLOW", "deniedAt": [], "allowedAt": allowed_at, "declarations": declarations}
        # -----------------------------------------------------
        # Undefined -> DENY
        # -----------------------------------------------------
        return { "allowed": False, "decision": "DEFAULT_DENY", "deniedAt": [], "allowedAt": [], "declarations": []}

    # =========================================================
    # NORMAL PERMISSIONS
    # =========================================================

    def resolve_permission( self, resource_path: str, security_group: str, permission: str) -> bool:
        """
        Backward-compatible boolean permission resolution.

        Detailed provenance is available through
        _permission_details().
        """
        details = self._permission_details( resource_path=resource_path, security_group=security_group, permission=permission)
        return details["allowed"]

    # =========================================================
    # OBLIGATIONS
    # =========================================================

    def resolve_obligations( self, resource_path: str, security_group: str) -> Dict[str, Any]:
        """
        Resolve row filters and column masks.

        row_filter:
            Most-specific non-null value wins.

        column_masks:
            Most-specific declaration wins for each column.
        """
        row_filter = None
        column_masks: Dict[str, Any] = {}
        row_filter_found = False
        for path in self._ancestor_paths( resource_path ):
            path_rules = self.rules.get( path, {})
            group_rule = path_rules.get( security_group )
            if group_rule is None:
                continue

            # -------------------------------------------------
            # Row filter
            # -------------------------------------------------
            if not row_filter_found:
                candidate = group_rule.get( "row_filter" )
                if candidate is not None:
                    row_filter = candidate
                    row_filter_found = True

            # -------------------------------------------------
            # Column masks
            # -------------------------------------------------
            masks = group_rule.get( "column_masks", {})
            if not isinstance( masks, dict):
                continue
            for column, expression in masks.items():
                # First value encountered is the
                # most-specific declaration.
                if column not in column_masks:
                    column_masks[column] = expression
        return { "row_filter": row_filter, "column_masks": column_masks}

    # =========================================================
    # ACTION
    # =========================================================

    def resolve_action( self, resource_path: str, security_group: str, action: str) -> Dict[str, Any]:
        """
        Resolve one action.

        The action is allowed only when every required permission
        is allowed.

        permissionResults:
            Simple boolean result for compatibility.

        permissionDetails:
            Detailed provenance for every required permission.
        """
        required_permissions = ( self.action_permissions.get( action ) )

        # -----------------------------------------------------
        # Unknown action
        # -----------------------------------------------------
        if required_permissions is None:
            return { "action": action, "allowed": False, "reason": "unknown_action", "requiredPermissions": [], "permissionResults": {}, "permissionDetails": {}, "row_filter": [], "column_masks": {}}
        permission_results: Dict[ str, bool] = {}
        permission_details: Dict[ str, Dict[str, Any]] = {}

        # -----------------------------------------------------
        # Resolve every required permission
        # -----------------------------------------------------
        for permission in required_permissions:
            details = self._permission_details( resource_path=resource_path, security_group=security_group, permission=permission)
            permission_results[ permission ] = details["allowed"]
            permission_details[ permission ] = details

        # -----------------------------------------------------
        # Resolve obligations
        # -----------------------------------------------------
        obligations = self.resolve_obligations( resource_path=resource_path, security_group=security_group)

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
            "row_filter": obligations[ "row_filter" ],
            "column_masks": obligations[ "column_masks" ],
        }

    # =========================================================
    # REWRITE
    # =========================================================

    def resolve_rewrite(self, rewrite: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Resolve one rewritten authorization object.

        expandedResources is authoritative for the concrete
        resources affected by the rewrite.

        expectedDecision records the intended behavior expressed
        by the rewrite:
            - ALLOW -> action is listed in rewrite["allowed"]
            - DENY  -> action is listed in rewrite["deny"]

        allowed records the actual result obtained by resolving
        the hierarchical policy.
        """
        security_group = rewrite.get("securityGroup")

        # ---------------------------------------------------------
        # Invalid / unknown security group
        # ---------------------------------------------------------
        if not rewrite.get("existSecureGroup", False):
            return []

        # ---------------------------------------------------------
        # Invalid action
        # ---------------------------------------------------------
        if not rewrite.get("actionExist", False):
            return []

        results: List[Dict[str, Any]] = []
        expanded_resources = rewrite.get("expandedResources", [])

        for expanded in expanded_resources:

            resource = {
                "catalog": expanded.get("catalogName", ""),
                "schema": expanded.get("schemaName", ""),
                "table": expanded.get("tableName", ""),
                "column": expanded.get("columnName", ""),
            }

            resource_path = self._resource_path(resource)
            resource_type = self._resource_type(resource)

            actions: Dict[str, Any] = {}

            # =====================================================
            # INTENDED ALLOW
            # =====================================================

            for action in rewrite.get("allowed", []):
                resolved = self.resolve_action(
                    resource_path=resource_path,
                    security_group=security_group,
                    action=action,
                )

                # Add the intended behavior from the rewrite.
                resolved["expectedDecision"] = "ALLOW"
                resolved["expectedAllowed"] = True
                resolved["expectationMatches"] = (
                        resolved["allowed"] is True
                )

                actions[action] = resolved

            # =====================================================
            # INTENDED DENY
            # =====================================================

            for action in rewrite.get("deny", []):

                required_permissions = self.action_permissions.get(
                    action,
                    []
                )

                permission_results: Dict[str, bool] = {}
                permission_details: Dict[str, Dict[str, Any]] = {}

                for permission in required_permissions:
                    details = self._permission_details(
                        resource_path=resource_path,
                        security_group=security_group,
                        permission=permission,
                    )

                    permission_results[permission] = details["allowed"]
                    permission_details[permission] = details

                actions[action] = {
                    "action": action,

                    # Actual policy result.
                    "allowed": False,

                    # Intended result from the rewrite.
                    "expectedDecision": "DENY",
                    "expectedAllowed": False,

                    # True when the actual result agrees with
                    # the intended behavior.
                    "expectationMatches": True,

                    "requiredPermissions": required_permissions,
                    "permissionResults": permission_results,
                    "permissionDetails": permission_details,

                    "row_filter": None,
                    "column_masks": {},

                    "reason": "explicit_rewrite_deny",
                }

            results.append(
                {
                    "securityGroup": security_group,
                    "resource": resource,
                    "resourcePath": resource_path,
                    "resourceType": resource_type,
                    "actions": actions,
                }
            )

        return results


    # =========================================================
    # RESOLVE EVERYTHING
    # =========================================================

    def resolve(self) -> List[Dict[str, Any]]:
        """
        Resolve every rewritten authorization object.
        """

        results: List[ Dict[str, Any] ] = []

        # Rewrite file can contain either:
        #
        #   [...]
        #
        # or:
        #
        #   {...}
        #
        # or:
        #
        #   {"rules": [...]}

        if isinstance( self.rewrites, list):
            rewrites = self.rewrites
        elif isinstance( self.rewrites, dict):
            if "securityGroup" in self.rewrites:
                rewrites = [ self.rewrites ]
            else:
                rewrites = self.rewrites.get( "rules", [])
        else:
            rewrites = []
        for rewrite in rewrites:
            results.extend( self.resolve_rewrite( rewrite ) )

        print("="*60)
        print("RESOLVER OUTPUT")
        print("="*60)
        print(json.dumps( results, indent=2, ensure_ascii=False ))

        return results

    # =========================================================
    # SAVE
    # =========================================================

    def save( self, output_file: str | Path) -> List[Dict[str, Any]]:
        results = self.resolve()
        output_file = Path( output_file )
        output_file.parent.mkdir( parents=True, exist_ok=True)
        with output_file.open( "w", encoding="utf-8") as f:
            json.dump( results, f, indent=2, ensure_ascii=False)
        return results
