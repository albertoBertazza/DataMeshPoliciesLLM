from copy import deepcopy
from typing import Any, Dict

class PolicyMerger:
    """
    Merge a newly compiled policy into an existing canonical policy.

    Permission semantics:

        existing: allow P
        new:      deny P
        result:   deny P

        existing: deny P
        new:      allow P
        result:   allow P

    Permissions not mentioned by the new policy are preserved.

    New resources and groups are added.

    Existing resources and groups are never removed.
    """

    def merge( self, existing_policy: Dict[str, Any], new_policy: Dict[str, Any]) -> Dict[str, Any]:

        result = deepcopy(existing_policy)

        result.setdefault( "version", "2.0-opa")

        existing_rules = result.setdefault( "rules", {})

        new_rules = new_policy.get( "rules", {})

        if not isinstance(existing_rules, dict):
            raise ValueError( "Existing policy 'rules' must be an object" )

        if not isinstance(new_rules, dict):
            raise ValueError( "New policy 'rules' must be an object" )

        for resource_id, new_groups in new_rules.items():

            if resource_id not in existing_rules:

                existing_rules[resource_id] = deepcopy( new_groups )

                continue

            existing_groups = existing_rules[ resource_id ]

            if not isinstance(existing_groups, dict):
                raise ValueError( f"Existing rules for resource " f"{resource_id!r} must be an object" )

            if not isinstance(new_groups, dict):
                raise ValueError( f"New rules for resource " f"{resource_id!r} must be an object" )

            for group, new_rule in new_groups.items():

                if group not in existing_groups:

                    existing_groups[group] = deepcopy( new_rule )

                    continue

                self._merge_rule( existing_rule=existing_groups[group], new_rule=new_rule)

        return result

    # ========================================================================
    # Rule merge
    # ========================================================================

    def _merge_rule( self, existing_rule: Dict[str, Any], new_rule: Dict[str, Any]) -> None:

        if not isinstance(existing_rule, dict):
            raise ValueError( "Existing rule must be an object" )

        if not isinstance(new_rule, dict):
            raise ValueError( "New rule must be an object" )

        # ------------------------------------------------------------
        # Keep metadata from existing rule.
        #
        # New metadata is used only when missing.
        # ------------------------------------------------------------

        for field in ( "rule_id", "group", "resource_type"):

            if field not in existing_rule and field in new_rule:
                existing_rule[field] = deepcopy( new_rule[field] )

        # ------------------------------------------------------------
        # Permissions
        # ------------------------------------------------------------

        existing_permissions = existing_rule.setdefault( "permissions", { "allow": [], "deny": []})

        new_permissions = new_rule.get( "permissions", {})

        if not isinstance( existing_permissions, dict):
            raise ValueError( "Existing rule permissions must be an object" )

        if not isinstance( new_permissions, dict):
            raise ValueError( "New rule permissions must be an object" )

        allow = set( existing_permissions.get( "allow", []) )

        deny = set( existing_permissions.get( "deny", []) )

        new_allow = set( new_permissions.get( "allow", []) )

        new_deny = set( new_permissions.get( "deny", []) )

        # ------------------------------------------------------------
        # New ALLOW
        #
        # ALLOW always becomes the current local status.
        # Therefore remove it from DENY.
        # ------------------------------------------------------------

        for permission in new_allow:

            deny.discard(permission)
            allow.add(permission)

        # ------------------------------------------------------------
        # New DENY
        #
        # DENY always becomes the current local status.
        # Therefore remove it from ALLOW.
        # ------------------------------------------------------------

        for permission in new_deny:

            allow.discard(permission)
            deny.add(permission)

        existing_permissions["allow"] = sorted( allow )

        existing_permissions["deny"] = sorted( deny )

        # ------------------------------------------------------------
        # Row filter
        #
        # If the new rule has no row filter:
        #     keep existing.
        #
        # If existing has no row filter:
        #     add new.
        #
        # If both exist and differ:
        #     fail rather than silently replacing security semantics.
        # ------------------------------------------------------------

        new_row_filter = new_rule.get( "row_filter" )

        if new_row_filter is not None:

            existing_row_filter = existing_rule.get( "row_filter" )

            if existing_row_filter is None:

                existing_rule["row_filter"] = ( new_row_filter )

            elif existing_row_filter != new_row_filter:

                raise ValueError( "Conflicting row filters for " f"group {new_rule.get('group')!r}" )

        # ------------------------------------------------------------
        # Column masks
        #
        # Existing masks are preserved.
        # New masks are added.
        # A different mask for the same column is rejected.
        # ------------------------------------------------------------

        existing_masks = existing_rule.setdefault( "column_masks", {})

        new_masks = new_rule.get( "column_masks", {})

        if not isinstance(existing_masks, dict):
            raise ValueError( "Existing column_masks must be an object" )

        if not isinstance(new_masks, dict):
            raise ValueError( "New column_masks must be an object" )

        for column, expression in new_masks.items():

            if column not in existing_masks:

                existing_masks[column] = expression

            elif existing_masks[column] != expression:

                raise ValueError( "Conflicting column masks for " f"column {column!r} " f"and group {new_rule.get('group')!r}" )
