import json
from pathlib import Path
from typing import Any, Dict, List

from Pipelines.B_TestAndEvaluationPipeline.A_TestGeneration.Resolver.draw_tree import print_permission_tree


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

    def resolve_action(
            self,
            resource_path: str,
            security_group: str,
            action: str,
    ) -> Dict[str, Any]:
        """
        Resolve one action against the resource target expressed
        by the authorization rule.

        The action is allowed only when every required permission
        is allowed.

        IMPORTANT:

        The resource_path is the depth explicitly expressed by the
        authorization rule.

        Example:

            Rule resource:
                root/iceberg

            CreateSchemaAction requires:
                AccessCatalog
                CreateSchema
                ExecuteQuery

            Resolution:

                AccessCatalog -> root/iceberg
                CreateSchema  -> root/iceberg
                ExecuteQuery  -> root

        Each permission walks the hierarchy from the supplied
        target toward root.
        """

        required_permissions = (
            self.action_permissions.get(action)
        )

        # -----------------------------------------------------
        # Unknown action
        # -----------------------------------------------------

        if required_permissions is None:
            return {
                "action": action,
                "allowed": False,
                "reason": "unknown_action",
                "requiredPermissions": [],
                "permissionResults": {},
                "permissionDetails": {},
                "row_filter": None,
                "column_masks": {},
            }

        # -----------------------------------------------------
        # Remove duplicate permissions while preserving order.
        #
        # Example:
        #
        # [
        #     "AccessCatalog",
        #     "CreateSchema",
        #     "ExecuteQuery",
        #     "CreateSchema"
        # ]
        #
        # becomes:
        #
        # [
        #     "AccessCatalog",
        #     "CreateSchema",
        #     "ExecuteQuery"
        # ]
        # -----------------------------------------------------

        required_permissions = list(
            dict.fromkeys(required_permissions)
        )

        permission_results: Dict[str, bool] = {}
        permission_details: Dict[str, Dict[str, Any]] = {}

        # -----------------------------------------------------
        # Resolve every required permission.
        #
        # IMPORTANT:
        #
        # Do NOT resolve against expandedResources.
        #
        # The resource_path is the resource explicitly expressed
        # by the rule.
        # -----------------------------------------------------

        for permission in required_permissions:
            details = self._permission_details(
                resource_path=resource_path,
                security_group=security_group,
                permission=permission,
            )

            permission_results[permission] = (
                details["allowed"]
            )

            permission_details[permission] = details

        # -----------------------------------------------------
        # Resolve obligations
        # -----------------------------------------------------

        obligations = self.resolve_obligations(
            resource_path=resource_path,
            security_group=security_group,
        )

        # -----------------------------------------------------
        # Action decision
        # -----------------------------------------------------

        allowed = all(
            permission_results.values()
        )

        return {
            "action": action,
            "allowed": allowed,
            "requiredPermissions": required_permissions,
            "permissionResults": permission_results,
            "permissionDetails": permission_details,
            "row_filter": obligations["row_filter"],
            "column_masks": obligations["column_masks"],
        }

    # =========================================================
    # REWRITE
    # =========================================================

    def resolve_rewrite(
            self,
            rewrite: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Resolve one rewritten authorization object.

        IMPORTANT RESOURCE SEMANTICS
        -----------------------------

        The explicit `resource` from the rewrite defines the
        authorization/test depth.

        Example:

            {
                "catalog": "iceberg",
                "schema": "",
                "table": "",
                "column": ""
            }

        means:

            resourcePath = root/iceberg
            resourceType = catalog

        It must produce ONE resolver target.

        `expandedResources` is NOT used to create authorization
        decisions.

        expandedResources may contain descendants such as:

            root/iceberg/hr/people
            root/iceberg/finance/employee_finance

        but these descendants do not become separate authorization
        targets.

        The permission resolver itself walks from the explicit rule
        target toward root.

        Therefore, for a catalog-level rule:

            CreateSchemaAction

        is resolved against:

            root/iceberg

        and its permissions can be found at:

            AccessCatalog -> root/iceberg
            CreateSchema  -> root/iceberg
            ExecuteQuery -> root

        The same principle applies at schema/table/column depth.
        """

        security_group = rewrite.get(
            "securityGroup"
        )

        # -----------------------------------------------------
        # Invalid / unknown security group
        # -----------------------------------------------------

        if not rewrite.get(
                "existSecureGroup",
                False,
        ):
            return []

        # -----------------------------------------------------
        # Invalid action
        # -----------------------------------------------------

        if not rewrite.get(
                "actionExist",
                False,
        ):
            return []

        # =====================================================
        # IMPORTANT:
        #
        # Use the ORIGINAL RESOURCE from the rule.
        #
        # Do NOT use expandedResources here.
        # =====================================================

        rule_resource = rewrite.get(
            "resource",
            {}
        )

        if not isinstance(
                rule_resource,
                dict,
        ):
            return []

        # -----------------------------------------------------
        # Make sure the resource has the standard shape.
        # -----------------------------------------------------

        resource = {
            "catalog": rule_resource.get(
                "catalog",
                "",
            ),
            "schema": rule_resource.get(
                "schema",
                "",
            ),
            "table": rule_resource.get(
                "table",
                "",
            ),
            "column": rule_resource.get(
                "column",
                "",
            ),
        }

        # -----------------------------------------------------
        # Determine the depth explicitly expressed by the rule.
        #
        # Example:
        #
        # iceberg
        #     -> catalog
        #
        # iceberg/hr
        #     -> schema
        #
        # iceberg/hr/people
        #     -> table
        #
        # iceberg/hr/people/name
        #     -> column
        # -----------------------------------------------------

        resource_path = self._resource_path(
            resource
        )

        resource_type = self._resource_type(
            resource
        )

        actions: Dict[str, Any] = {}

        # =====================================================
        # INTENDED ALLOW
        # =====================================================

        for action in rewrite.get(
                "allowed",
                [],
        ):
            resolved = self.resolve_action(
                resource_path=resource_path,
                security_group=security_group,
                action=action,
            )

            # -------------------------------------------------
            # Add intended behavior from the rewrite.
            # -------------------------------------------------

            resolved["expectedDecision"] = "ALLOW"

            resolved["expectedAllowed"] = True

            resolved["expectationMatches"] = (
                    resolved["allowed"] is True
            )

            actions[action] = resolved

        # =====================================================
        # INTENDED DENY
        # =====================================================

        for action in rewrite.get(
                "deny",
                [],
        ):

            required_permissions = (
                self.action_permissions.get(
                    action,
                    [],
                )
            )

            # Remove duplicates while preserving order.
            required_permissions = list(
                dict.fromkeys(
                    required_permissions
                )
            )

            permission_results: Dict[
                str,
                bool,
            ] = {}

            permission_details: Dict[
                str,
                Dict[str, Any],
            ] = {}

            for permission in required_permissions:
                details = self._permission_details(
                    resource_path=resource_path,
                    security_group=security_group,
                    permission=permission,
                )

                permission_results[permission] = (
                    details["allowed"]
                )

                permission_details[permission] = (
                    details
                )

            actions[action] = {
                "action": action,

                # Actual policy result is intentionally
                # represented separately from the rewrite
                # expectation.
                "allowed": False,

                "expectedDecision": "DENY",
                "expectedAllowed": False,

                "expectationMatches": True,

                "requiredPermissions": (
                    required_permissions
                ),

                "permissionResults": (
                    permission_results
                ),

                "permissionDetails": (
                    permission_details
                ),

                "row_filter": None,
                "column_masks": {},

                "reason": (
                    "explicit_rewrite_deny"
                ),
            }

        # =====================================================
        # ONE RESULT FOR THE EXPLICIT RULE RESOURCE
        # =====================================================

        return [
            {
                "securityGroup": security_group,

                # This is the resource depth expressed
                # by the rule.
                "resource": resource,

                "resourcePath": resource_path,

                "resourceType": resource_type,

                "actions": actions,
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
        #print(json.dumps( results, indent=2, ensure_ascii=False ))
        print_permission_tree(results)

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
